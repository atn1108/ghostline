//go:build windows

package vpn

import (
	"io"
	"os"
	"os/exec"

	"github.com/hashcott/ghostline/internal/winutil"
)

// newCmd starts openvpn without a console window.
func newCmd(exe string, args []string) *exec.Cmd { return winutil.HiddenCmd(exe, args, "") }

// guard ties openvpn to Ghostline: a crashed Ghostline takes the tunnel down
// instead of leaving an orphan holding the adapter and its routes.
func guard(p *os.Process) io.Closer {
	job, err := winutil.NewKillOnCloseJob()
	if err != nil {
		return nil
	}
	if err := job.Assign(p); err != nil {
		_ = job.Close()
		return nil
	}
	return job
}

// dnsLeakArgs stops Windows Smart Multi-Homed Name Resolution from leaking DNS
// to the physical adapter when Ghostline's own encrypted DNS is off; when
// Ghostline's DNS is active, ignore pushed block-outside-dns so 127.0.0.1 stays
// reachable.
func dnsLeakArgs(keepLocalDNS bool) []string {
	if keepLocalDNS {
		return []string{"--pull-filter", "ignore", "block-outside-dns"}
	}
	return []string{"--block-outside-dns"}
}
