//go:build windows

package vpn

import (
	"os"
	"path/filepath"
)

// candidates lists where the OpenVPN community installer puts openvpn.exe.
func candidates() []string {
	var out []string
	for _, env := range []string{"ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"} {
		if dir := os.Getenv(env); dir != "" {
			out = append(out, filepath.Join(dir, "OpenVPN", "bin", "openvpn.exe"))
		}
	}
	if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
		out = append(out, filepath.Join(dir, "Programs", "OpenVPN", "bin", "openvpn.exe"))
	}
	return out
}
