package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashcott/ghostline/internal/vpn"
	"github.com/stretchr/testify/require"
)

func newVPN(t *testing.T) *svcHarness {
	t.Helper()
	h := newSvc(t)
	h.svc.x.VPNStore = vpn.NewStore(h.paths.DataDir)
	h.svc.x.VPN = vpn.NewManager()
	return h
}

func TestVPNService_AddValidationAndErrors(t *testing.T) {
	h := newVPN(t)

	_, err := h.svc.VPNAdd("empty.ovpn", "   ")
	require.Equal(t, CodeVPNBadConfig, code(t, err))

	_, err = h.svc.VPNAdd("evil.ovpn", "remote 1.2.3.4\nup /bin/sh\n")
	require.Equal(t, CodeVPNUnsafe, code(t, err))

	_, err = h.svc.VPNAdd("ext.ovpn", "remote 1.2.3.4\nca ca.crt\n")
	require.Equal(t, CodeVPNExternal, code(t, err))

	p, err := h.svc.VPNAdd("vpngate_JP_219.100.37.104_tcp.ovpn", "dev tun\nproto tcp\nremote 219.100.37.104 443\n")
	require.NoError(t, err)
	require.Equal(t, "vpngate_JP_219.100.37.104_tcp", p.Name)

	info := h.svc.VPNInfo()
	require.True(t, info.Supported)
	require.Len(t, info.Profiles, 1)

	require.NoError(t, h.svc.VPNDelete(p.ID))
	require.Empty(t, h.svc.VPNInfo().Profiles)
}

func TestVPNService_SetBinaryAndConnectChecks(t *testing.T) {
	h := newVPN(t)

	dir := t.TempDir()
	err := h.svc.VPNSetBinary(dir)
	require.Equal(t, CodeVPNBinaryMissing, code(t, err))

	err = h.svc.VPNSetBinary(filepath.Join(dir, "missing-openvpn"))
	require.Equal(t, CodeVPNBinaryMissing, code(t, err))

	fakeBin := filepath.Join(dir, "openvpn")
	require.NoError(t, os.WriteFile(fakeBin, []byte(""), 0o755))
	require.NoError(t, h.svc.VPNSetBinary(fakeBin))
	require.Equal(t, fakeBin, h.svc.VPNInfo().Binary)

	p, err := h.svc.VPNAdd("auth.ovpn", "remote 1.2.3.4 443\nauth-user-pass\n")
	require.NoError(t, err)

	err = h.svc.VPNConnect(p.ID, "", "")
	require.Equal(t, CodeVPNNeedsAuth, code(t, err))

	err = h.svc.VPNConnect("0000000000000000", "u", "p")
	require.Equal(t, CodeVPNBadConfig, code(t, err))
}

func TestVPNService_UnsupportedWhenUnwired(t *testing.T) {
	h := newSvc(t)
	info := h.svc.VPNInfo()
	require.False(t, info.Supported)

	_, err := h.svc.VPNAdd("a.ovpn", "remote 1.2.3.4\n")
	require.Equal(t, CodeVPNUnsupported, code(t, err))
	require.Equal(t, CodeVPNUnsupported, code(t, h.svc.VPNConnect("id", "", "")))
	require.Equal(t, CodeVPNUnsupported, code(t, h.svc.VPNDelete("id")))
	require.Equal(t, CodeVPNUnsupported, code(t, h.svc.VPNSetBinary("")))
}
