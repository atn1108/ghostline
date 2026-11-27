package core

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

type stubDialResolver struct{ addrs []netip.Addr }

func (s stubDialResolver) Resolve(context.Context, string) ([]netip.Addr, error) {
	return s.addrs, nil
}

func TestVPNResolver_DropsIPv6WhileBlocking(t *testing.T) {
	v6 := netip.MustParseAddr("2606:4700:4700::1111")
	v4 := netip.MustParseAddr("1.1.1.1")
	blocking := false
	r := vpnResolver{base: stubDialResolver{addrs: []netip.Addr{v6, v4}}, blockingIPv6: func() bool { return blocking }}

	// Idle: both IPv6 and IPv4 pass through.
	got, err := r.Resolve(context.Background(), "one.one.one.one")
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{v6, v4}, got)

	// Active IPv4-only VPN: only IPv4 passes through.
	blocking = true
	got, err = r.Resolve(context.Background(), "one.one.one.one")
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{v4}, got)

	// IPv6-only target returns an error rather than leaking IPv6.
	rOnly6 := vpnResolver{base: stubDialResolver{addrs: []netip.Addr{v6}}, blockingIPv6: func() bool { return true }}
	_, err = rOnly6.Resolve(context.Background(), "ipv6.test")
	require.Error(t, err)
}
