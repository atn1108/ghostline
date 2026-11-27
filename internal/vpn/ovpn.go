// Package vpn imports OpenVPN profiles (.ovpn) and runs the OpenVPN client
// that is installed on the machine.
//
// Ghostline does not implement the tunnel itself: it keeps the profile the
// user imported, starts openvpn on it, follows the client's own log and
// management interface for the state, and stops it cleanly. Profiles that
// would run commands or read other files are refused: on Linux the daemon
// runs as root, and an .ovpn is just a text file someone else may have
// written.
package vpn

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Config is what Ghostline reads from an .ovpn file.
type Config struct {
	Host    string
	Port    int
	Proto   string
	Dev     string
	Remotes int
	HasIPv6 bool
	// NeedsAuth is true when the profile asks for a username and password
	// (auth-user-pass with no file).
	NeedsAuth bool
}

var (
	// ErrUnsafe: the profile runs commands or writes files, which Ghostline
	// refuses to hand to openvpn.
	ErrUnsafe = errors.New("vpn: the profile runs commands")
	// ErrExternal: the profile points at files next to it instead of
	// embedding them.
	ErrExternal = errors.New("vpn: the profile refers to external files")
)

// unsafeDirectives lists directives that execute programs, read or write files, or
// hand openvpn's console to someone else. OpenVPN's default script-security
// allows user scripts, so these never reach the client.
var unsafeDirectives = map[string]bool{
	"config": true, "cd": true,
	"plugin": true, "up": true, "down": true, "route-up": true, "route-pre-down": true,
	"ipchange": true, "learn-address": true, "client-connect": true, "client-disconnect": true,
	"auth-user-pass-verify": true, "tls-verify": true, "client-crresponse": true,
	"script-security": true,
	"iproute":         true,
	"daemon":          true, "log": true, "log-append": true, "writepid": true, "status": true,
	"management": true, "management-client": true, "management-hold": true,
	"management-signal": true, "management-query-passwords": true, "management-forget-disconnect": true,
	"askpass": true, "auth-gen-token-secret": true,
}

// external lists directives whose argument is a file next to the profile.
// Inline blocks (<ca>…</ca>) are embedded and therefore fine.
var external = map[string]bool{
	"ca": true, "cert": true, "key": true, "dh": true, "extra-certs": true, "secret": true,
	"pkcs12": true, "crl-verify": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true,
	"auth-user-pass": true,
}

// Parse reads the directives Ghostline needs. It does not validate the
// profile for OpenVPN itself: openvpn does that when it starts.
func Parse(text string) (Config, error) {
	c := Config{Port: 1194}
	hasRemotePort := false
	hasGlobalPort := false
	text = strings.TrimPrefix(text, "\ufeff")
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	block := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if block != "" {
			if strings.EqualFold(line, "</"+block+">") {
				block = ""
			}
			continue
		}
		if len(line) > 2 && line[0] == '<' && line[len(line)-1] == '>' {
			tag := strings.Trim(line, "<>")
			// </…> closes a block, and <connection> only groups ordinary
			// directives: neither hides the lines that follow.
			if strings.HasPrefix(tag, "/") || strings.EqualFold(tag, "connection") {
				continue
			}
			block = tag
			continue
		}
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		f := strings.Fields(line)
		name := strings.ToLower(f[0])
		args := f[1:]
		if unsafeDirectives[name] {
			return Config{}, fmt.Errorf("%w: %s", ErrUnsafe, name)
		}
		if external[name] && len(args) > 0 {
			return Config{}, fmt.Errorf("%w: %s %s", ErrExternal, name, args[0])
		}
		switch name {
		case "remote":
			if len(args) == 0 {
				return Config{}, fmt.Errorf("vpn: remote without a host")
			}
			if c.Remotes == 0 {
				c.Host = args[0]
				if len(args) > 1 {
					if p, err := strconv.Atoi(args[1]); err == nil && p > 0 && p < 65536 {
						c.Port = p
						hasRemotePort = true
					}
				}
				if len(args) > 2 {
					c.Proto = normalizeProto(args[2])
				}
			}
			c.Remotes++
		case "port", "rport":
			if !hasRemotePort && !hasGlobalPort && len(args) > 0 {
				if p, err := strconv.Atoi(args[0]); err == nil && p > 0 && p < 65536 {
					c.Port = p
					hasGlobalPort = true
				}
			}
		case "proto":
			if len(args) > 0 {
				c.Proto = normalizeProto(args[0])
			}
		case "dev":
			if len(args) > 0 {
				c.Dev = args[0]
			}
		case "ifconfig-ipv6", "route-ipv6", "tun-ipv6":
			c.HasIPv6 = true
		case "auth-user-pass":
			// With no argument openvpn asks on the console; Ghostline hands
			// it a credentials file instead. With one, it was refused above.
			c.NeedsAuth = true
		}
	}
	if block != "" {
		return Config{}, fmt.Errorf("vpn: unterminated <%s> block", block)
	}
	if c.Host == "" {
		return Config{}, fmt.Errorf("vpn: the profile has no remote")
	}
	if c.Proto == "" {
		c.Proto = "udp"
	}
	return c, nil
}

// normalizeProto folds openvpn's protocol names into tcp/udp for the UI.
func normalizeProto(p string) string {
	p = strings.ToLower(p)
	switch {
	case strings.HasPrefix(p, "tcp"):
		return "tcp"
	case strings.HasPrefix(p, "udp"):
		return "udp"
	}
	return p
}
