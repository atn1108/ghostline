//go:build !windows

package vpn

import (
	"io"
	"os"
	"os/exec"
)

// newCmd starts openvpn in the daemon's process group.
func newCmd(exe string, args []string) *exec.Cmd { return exec.Command(exe, args...) }

// guard is Windows-only: elsewhere openvpn gets SIGTERM from Stop.
func guard(*os.Process) io.Closer { return nil }

// dnsLeakArgs ignores Windows-only block-outside-dns directives on non-Windows.
func dnsLeakArgs(bool) []string {
	return []string{"--pull-filter", "ignore", "block-outside-dns"}
}
