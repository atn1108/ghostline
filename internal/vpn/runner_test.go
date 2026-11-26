package vpn

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	if os.Getenv("GO_WANT_VPN_HELPER") == "1" {
		os.Exit(runHelperProcess())
	}
	os.Exit(m.Run())
}

// runHelperProcess mimics openvpn: prints log lines, opens the --management
// TCP listener, reports >STATE:...,CONNECTED and exits cleanly on signal SIGTERM.
func runHelperProcess() int {
	var mgmtAddr, authFile string
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--management":
			if i+2 < len(os.Args) {
				mgmtAddr = net.JoinHostPort(os.Args[i+1], os.Args[i+2])
				i += 2
			}
		case "--auth-user-pass":
			if i+1 < len(os.Args) {
				authFile = os.Args[i+1]
				i++
			}
		case "--block-ipv6", "--block-outside-dns":
			fmt.Println("flag=" + os.Args[i])
		}
	}
	switch os.Getenv("VPN_HELPER_MODE") {
	case "auth_failed":
		fmt.Println("AUTH: Received control message: AUTH_FAILED")
		fmt.Println("SIGTERM[soft,auth-failure] received, process exiting")
		return 0
	case "fatal":
		fmt.Fprintln(os.Stderr, "Options error: Unrecognized option")
		return 1
	}

	if authFile != "" {
		b, err := os.ReadFile(authFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Options error: missing auth file")
			return 1
		}
		fmt.Printf("auth_loaded=%d\n", len(strings.TrimSpace(string(b))))
	}

	l, err := net.Listen("tcp", mgmtAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Exiting due to fatal error:", err)
		return 1
	}
	defer func() { _ = l.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		sc := bufio.NewScanner(c)
		for sc.Scan() {
			cmd := strings.TrimSpace(sc.Text())
			if cmd == "state on" {
				_, _ = fmt.Fprintln(c, ">STATE:1,CONNECTED,SUCCESS,10.8.0.2,219.100.37.104")
			}
			if cmd == "signal SIGTERM" {
				fmt.Println("SIGTERM[hard,] received, process exiting")
				return
			}
		}
	}()

	fmt.Println("Initialization Sequence Completed")
	<-done
	return 0
}

func waitPhase(t *testing.T, m *Manager, want string) Status {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := m.Status()
		if st.Phase == want {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for phase %q (got %+v)", want, m.Status())
	return Status{}
}

func TestManager_ConnectAndGracefulStop(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)
	t.Setenv("GO_WANT_VPN_HELPER", "1")
	t.Setenv("VPN_HELPER_MODE", "ok")

	cfgPath := filepath.Join(t.TempDir(), "test.ovpn")
	require.NoError(t, os.WriteFile(cfgPath, []byte("remote 1.2.3.4 443\n"), 0o600))

	var mu sync.Mutex
	var events []Status
	m := NewManager()
	m.SetNotify(func(st Status) {
		mu.Lock()
		events = append(events, st)
		mu.Unlock()
	})

	require.NoError(t, m.Start(exe, "p1", cfgPath, "vpn", "vpn", StartOptions{BlockIPv6: true}))
	st := waitPhase(t, m, PhaseConnected)
	require.Equal(t, "p1", st.ProfileID)
	require.NotZero(t, st.Since)
	require.True(t, m.Running())
	require.True(t, m.BlockingIPv6())
	require.Contains(t, st.Log, "flag=--block-ipv6")

	m.Stop()
	st = waitPhase(t, m, PhaseIdle)
	require.Empty(t, st.ProfileID)
	require.Empty(t, st.Error)
	require.False(t, m.Running())
	require.False(t, m.BlockingIPv6())
	_, err = os.Stat(cfgPath + ".auth")
	require.ErrorIs(t, err, os.ErrNotExist)

	mu.Lock()
	require.NotEmpty(t, events)
	mu.Unlock()
}

func TestManager_AuthFailedAndClearIfProfile(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)
	t.Setenv("GO_WANT_VPN_HELPER", "1")
	t.Setenv("VPN_HELPER_MODE", "auth_failed")

	cfgPath := filepath.Join(t.TempDir(), "auth.ovpn")
	require.NoError(t, os.WriteFile(cfgPath, []byte("remote 1.2.3.4 443\n"), 0o600))

	m := NewManager()
	require.NoError(t, m.Start(exe, "p1", cfgPath, "u", "wrong", StartOptions{}))
	st := waitPhase(t, m, PhaseError)
	require.Equal(t, "AUTH_FAILED", st.Error)
	require.Equal(t, "p1", st.ProfileID)

	m.ClearIfProfile("other")
	require.Equal(t, PhaseError, m.Status().Phase)
	m.ClearIfProfile("p1")
	require.Equal(t, PhaseIdle, m.Status().Phase)
	require.Empty(t, m.Status().ProfileID)
}

func TestManager_FatalStderrLine(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)
	t.Setenv("GO_WANT_VPN_HELPER", "1")
	t.Setenv("VPN_HELPER_MODE", "fatal")

	cfgPath := filepath.Join(t.TempDir(), "bad.ovpn")
	require.NoError(t, os.WriteFile(cfgPath, []byte("remote 1.2.3.4 443\n"), 0o600))

	m := NewManager()
	require.NoError(t, m.Start(exe, "p2", cfgPath, "", "", StartOptions{}))
	st := waitPhase(t, m, PhaseError)
	require.Contains(t, st.Error, "Options error: Unrecognized option")
}
