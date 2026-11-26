package vpn

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Phases of the tunnel, as the page shows them.
const (
	PhaseIdle      = "idle"
	PhaseStarting  = "starting"
	PhaseConnected = "connected"
	PhaseError     = "error"
)

// Status is the OpenVPN client's state.
type Status struct {
	Phase     string   `json:"phase"`
	ProfileID string   `json:"profileId"`
	Since     int64    `json:"since"` // unix milliseconds; 0 unless connected
	Error     string   `json:"error"`
	Log       []string `json:"log"`
}

// logLines is how much of openvpn's own log stays in RAM.
const logLines = 300

// StartOptions controls leak protection around the OpenVPN client.
type StartOptions struct {
	// BlockIPv6 prevents IPv6 traffic from bypassing an IPv4-only tunnel.
	BlockIPv6 bool
	// KeepLocalDNS preserves Ghostline's own encrypted DNS instead of letting
	// OpenVPN block non-tunnel DNS lookups on Windows.
	KeepLocalDNS bool
}

// Manager runs one OpenVPN client at a time.
type Manager struct {
	mu           sync.Mutex
	status       Status
	log          []string
	cmd          *exec.Cmd
	guard        io.Closer
	ks           *killSwitch
	mgmt         net.Conn
	done         chan struct{}
	stopping     bool
	blockingIPv6 bool
	notify       func(Status)
}

// NewManager returns a stopped manager.
func NewManager() *Manager {
	return &Manager{status: Status{Phase: PhaseIdle}, notify: func(Status) {}}
}

// SetNotify receives a copy of the status after every change.
func (m *Manager) SetNotify(f func(Status)) {
	m.mu.Lock()
	m.notify = f
	m.mu.Unlock()
}

// Status returns the current state with the log.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	s.Log = append([]string(nil), m.log...)
	return s
}

// Running reports whether an OpenVPN client is alive.
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cmd != nil
}

// BlockingIPv6 reports whether an IPv4-only VPN tunnel is currently active
// with IPv6 leak blocking enabled.
func (m *Manager) BlockingIPv6() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cmd != nil && m.blockingIPv6
}

// Start runs openvpn on the stored config. user and pass feed an
// auth-user-pass profile through a private file, never through the command
// line.
func (m *Manager) Start(binary, profileID, configPath, user, pass string, opts StartOptions) error {
	m.mu.Lock()
	if m.cmd != nil {
		m.mu.Unlock()
		return errors.New("vpn: OpenVPN is already running")
	}
	m.status = Status{Phase: PhaseStarting, ProfileID: profileID}
	m.log = nil
	m.stopping = false
	m.blockingIPv6 = opts.BlockIPv6
	m.mu.Unlock()
	m.publish()

	authFile := ""
	if user != "" || pass != "" {
		authFile = configPath + ".auth"
		if err := os.WriteFile(authFile, []byte(user+"\n"+pass+"\n"), 0o600); err != nil {
			err = fmt.Errorf("vpn: writing the credentials: %w", err)
			m.fail(err)
			return err
		}
	} else {
		_ = os.Remove(configPath + ".auth")
	}
	port, err := freePort()
	if err != nil {
		removeIfSet(authFile)
		m.fail(err)
		return err
	}
	args := []string{
		"--config", configPath,
		"--verb", "3",
		// The profile was checked for script directives, but say it again:
		// no program may run as Ghostline's user (root on Linux).
		"--script-security", "0",
		// The management interface gives the state and a clean stop.
		"--management", "127.0.0.1", strconv.Itoa(port),
	}
	args = append(args, dnsLeakArgs(opts.KeepLocalDNS)...)
	if opts.BlockIPv6 {
		args = append(args, "--block-ipv6")
	}
	if authFile != "" {
		args = append(args, "--auth-user-pass", authFile)
	}
	cmd := newCmd(binary, args)
	out, err := cmd.StdoutPipe()
	if err != nil {
		removeIfSet(authFile)
		err = fmt.Errorf("vpn: capturing openvpn's log: %w", err)
		m.fail(err)
		return err
	}
	errp, err := cmd.StderrPipe()
	if err != nil {
		removeIfSet(authFile)
		err = fmt.Errorf("vpn: capturing openvpn's log: %w", err)
		m.fail(err)
		return err
	}
	ks, ksErr := startKillSwitch(binary)
	if ksErr != nil {
		m.addLog("vpn: kill switch unavailable: " + ksErr.Error())
	} else if ks != nil {
		m.addLog("vpn: kill switch active (blocking non-VPN traffic)")
	}
	if err := cmd.Start(); err != nil {
		if ks != nil {
			_ = ks.Close()
		}
		removeIfSet(authFile)
		err = fmt.Errorf("vpn: starting openvpn: %w", err)
		m.fail(err)
		return err
	}
	done := make(chan struct{})
	m.mu.Lock()
	m.cmd = cmd
	m.guard = guard(cmd.Process)
	m.ks = ks
	m.done = done
	m.mu.Unlock()

	var pipesWG sync.WaitGroup
	pipesWG.Add(2)
	go func() { defer pipesWG.Done(); m.read(out) }()
	go func() { defer pipesWG.Done(); m.read(errp) }()
	go m.manage(port, done)
	go m.wait(cmd, &pipesWG, done, authFile)
	return nil
}

// ClearIfProfile resets a stopped error state belonging to profileID.
func (m *Manager) ClearIfProfile(profileID string) {
	m.mu.Lock()
	if m.cmd != nil || m.status.ProfileID != profileID {
		m.mu.Unlock()
		return
	}
	m.status = Status{Phase: PhaseIdle}
	m.mu.Unlock()
	m.publish()
}

// Stop ends the tunnel: openvpn is asked to exit through its management
// interface so it removes routes and the adapter, and is killed only if it
// does not answer.
func (m *Manager) Stop() {
	m.mu.Lock()
	cmd, conn, done := m.cmd, m.mgmt, m.done
	if cmd == nil {
		m.mu.Unlock()
		return
	}
	m.stopping = true
	m.mu.Unlock()

	if conn != nil {
		_, _ = conn.Write([]byte("signal SIGTERM\n"))
	}
	if done != nil {
		select {
		case <-done:
			return
		case <-time.After(8 * time.Second):
		}
	}
	_ = cmd.Process.Kill()
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
}

func (m *Manager) wait(cmd *exec.Cmd, pipesWG *sync.WaitGroup, done chan struct{}, authFile string) {
	// Drain stdout/stderr before cmd.Wait closes the pipes and before we
	// inspect m.status.Error for any failure line printed just before exit.
	pipesWG.Wait()
	err := cmd.Wait()
	close(done)
	removeIfSet(authFile)

	m.mu.Lock()
	if m.mgmt != nil {
		_ = m.mgmt.Close()
		m.mgmt = nil
	}
	m.cmd = nil
	m.blockingIPv6 = false
	ks := m.ks
	m.ks = nil
	if m.guard != nil {
		_ = m.guard.Close()
		m.guard = nil
	}
	stopping, reason, phase := m.stopping, m.status.Error, m.status.Phase
	m.stopping = false
	m.status.Since = 0
	switch {
	case stopping:
		m.status.Phase = PhaseIdle
		m.status.ProfileID = ""
		m.status.Error = ""
	case err != nil:
		m.status.Phase = PhaseError
		m.status.Error = firstNonEmpty(reason, err.Error())
	case phase == PhaseConnected:
		// openvpn ended on its own after a working tunnel.
		m.status.Phase = PhaseIdle
		m.status.ProfileID = ""
		m.status.Error = ""
	default:
		m.status.Phase = PhaseError
		m.status.Error = firstNonEmpty(reason, "openvpn exited")
	}
	m.mu.Unlock()
	if ks != nil {
		_ = ks.Close()
	}
	m.publish()
}

// read copies openvpn's own log into RAM and watches for the two lines that
// matter: the tunnel is up, or it failed.
func (m *Manager) read(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.Contains(line, "Initialization Sequence Completed"):
			m.refreshKillSwitch()
			m.connected()
		case strings.Contains(line, "AUTH_FAILED"):
			m.noteError("AUTH_FAILED")
		case strings.Contains(line, "Exiting due to fatal error"), strings.Contains(line, "Options error"):
			m.noteError(strings.TrimSpace(line))
		}
		m.addLog(line)
	}
}

// manage follows the management interface for the tunnel state and answers
// Stop with a graceful exit.
func (m *Manager) manage(port int, done chan struct{}) {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	var conn net.Conn
	for i := 0; i < 60; i++ {
		select {
		case <-done:
			return
		default:
		}
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn = c
			break
		}
		select {
		case <-done:
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
	if conn == nil {
		m.addLog("openvpn: management interface unavailable; stopping will fall back to kill")
		return
	}
	m.mu.Lock()
	if m.cmd == nil {
		m.mu.Unlock()
		_ = conn.Close()
		return
	}
	m.mgmt = conn
	stopping := m.stopping
	m.mu.Unlock()

	if stopping {
		_, _ = conn.Write([]byte("signal SIGTERM\n"))
		return
	}

	_, _ = conn.Write([]byte("state on\n"))
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, ">STATE:") {
			continue
		}
		f := strings.Split(strings.TrimPrefix(line, ">STATE:"), ",")
		if len(f) < 2 {
			continue
		}
		switch f[1] {
		case "CONNECTED":
			m.refreshKillSwitch()
			m.connected()
		case "ASSIGN_IP", "ADD_ROUTES":
			m.refreshKillSwitch()
			m.starting()
		case "RECONNECTING", "RESOLVE", "TCP_CONNECT", "WAIT", "AUTH", "GET_CONFIG":
			m.starting()
		}
	}
}

func (m *Manager) refreshKillSwitch() {
	m.mu.Lock()
	ks := m.ks
	m.mu.Unlock()
	if ks != nil {
		if err := ks.Refresh(); err != nil {
			m.addLog("vpn: kill switch refresh failed: " + err.Error())
		}
	}
}

func (m *Manager) connected() {
	m.mu.Lock()
	if m.cmd == nil || m.stopping || m.status.Phase == PhaseConnected {
		m.mu.Unlock()
		return
	}
	m.status.Phase = PhaseConnected
	m.status.Since = time.Now().UnixMilli()
	m.status.Error = ""
	m.mu.Unlock()
	m.publish()
}

func (m *Manager) starting() {
	m.mu.Lock()
	if m.cmd == nil || m.stopping || m.status.Phase == PhaseStarting {
		m.mu.Unlock()
		return
	}
	m.status.Phase = PhaseStarting
	m.status.Since = 0
	m.mu.Unlock()
	m.publish()
}

func (m *Manager) noteError(msg string) {
	m.mu.Lock()
	m.status.Error = msg
	m.mu.Unlock()
}

func (m *Manager) fail(err error) {
	m.mu.Lock()
	m.blockingIPv6 = false
	m.status.Phase = PhaseError
	m.status.Error = err.Error()
	m.status.Since = 0
	m.mu.Unlock()
	m.publish()
}

func (m *Manager) addLog(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	m.mu.Lock()
	m.log = append(m.log, line)
	if len(m.log) > logLines {
		m.log = m.log[len(m.log)-logLines:]
	}
	m.mu.Unlock()
	m.publish()
}

func (m *Manager) publish() {
	m.mu.Lock()
	s := m.status
	s.Log = append([]string(nil), m.log...)
	f := m.notify
	m.mu.Unlock()
	if f != nil {
		f(s)
	}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("vpn: finding a management port: %w", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func removeIfSet(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
