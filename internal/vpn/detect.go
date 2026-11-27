package vpn

import (
	"os"
	"os/exec"
)

// Detect returns the openvpn executable to run: the configured path when it
// still exists, otherwise the usual install locations, otherwise PATH.
// "" means OpenVPN is not installed.
func Detect(configured string) string {
	if configured != "" && isFile(configured) {
		return configured
	}
	for _, p := range candidates() {
		if isFile(p) {
			return p
		}
	}
	if p, err := exec.LookPath("openvpn"); err == nil {
		return p
	}
	return ""
}

func isFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
