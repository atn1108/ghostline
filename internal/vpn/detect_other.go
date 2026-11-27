//go:build !windows

package vpn

// candidates lists the usual places distributions install the openvpn
// client.
func candidates() []string {
	return []string{
		"/usr/sbin/openvpn",
		"/usr/bin/openvpn",
		"/sbin/openvpn",
		"/usr/local/sbin/openvpn",
		"/usr/local/bin/openvpn",
	}
}
