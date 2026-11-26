//go:build windows

package vpn

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestKillSwitch_Win32StructLayouts(t *testing.T) {
	// Verify x64 Windows SDK (fwpmtypes.h / fwptypes.h) struct sizes & offsets.
	if unsafe.Sizeof(uintptr(0)) == 8 {
		require.Equal(t, uintptr(16), unsafe.Sizeof(fwpByteBlob{}))
		require.Equal(t, uintptr(16), unsafe.Sizeof(fwpValue0{}))
		require.Equal(t, uintptr(72), unsafe.Sizeof(fwpmSession0{}))
		require.Equal(t, uintptr(72), unsafe.Sizeof(fwpmSubLayer0{}))
		require.Equal(t, uintptr(40), unsafe.Sizeof(fwpmFilterCondition0{}))
		require.Equal(t, uintptr(200), unsafe.Sizeof(fwpmFilter0{}))
		var f fwpmFilter0
		require.Equal(t, uintptr(128), unsafe.Offsetof(f.action))
		require.Equal(t, uintptr(152), unsafe.Offsetof(f.rawContext))
		require.Equal(t, uintptr(176), unsafe.Offsetof(f.filterId))
	}
}

func TestKillSwitch_Helpers(t *testing.T) {
	m4, err := parseV4Mask("127.0.0.0/8")
	require.NoError(t, err)
	require.Equal(t, uint32(0x7f000000), m4.addr)
	require.Equal(t, uint32(0xff000000), m4.mask)

	m6, err := parseV6Mask("::1/128")
	require.NoError(t, err)
	require.Equal(t, uint8(128), m6.prefixLength)
	require.Equal(t, byte(1), m6.addr[15])

	require.True(t, isVPNAdapter(ifTypePropVirtual, "TAP-Windows Adapter V9", "Local Area Connection"))
	require.True(t, isVPNAdapter(ifTypePropVirtual, "OpenVPN Data Channel Offload", "OpenVPN Data Channel Offload"))
	require.True(t, isVPNAdapter(ifTypePropVirtual, "Wintun Userspace Tunnel", "tun"))
	require.False(t, isVPNAdapter(6, "Intel(R) Wi-Fi 6", "Wi-Fi"))
}
