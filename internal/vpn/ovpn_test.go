package vpn

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse_VPNGateStyle(t *testing.T) {
	cfgText := "\ufeff" + `
dev tun
proto tcp
;http-proxy-retry
cipher AES-128-CBC
client
  remote 219.100.37.104 443
  remote 219.100.37.104 995
  remote 219.100.37.104 1194
  remote 219.100.37.104 992
#auth-user-pass
<ca>
up /bin/sh
-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIC
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN RSA PRIVATE KEY-----
MIIE
-----END RSA PRIVATE KEY-----
</key>
`
	c, err := Parse(cfgText)
	require.NoError(t, err)
	require.Equal(t, Config{
		Host:      "219.100.37.104",
		Port:      443,
		Proto:     "tcp",
		Dev:       "tun",
		Remotes:   4,
		NeedsAuth: false,
	}, c)
}

func TestParse_GlobalPortAndConnectionBlock(t *testing.T) {
	cfgText := `
port 443
<connection>
remote vpn.example.com
proto tcp-client
</connection>
auth-user-pass
`
	c, err := Parse(cfgText)
	require.NoError(t, err)
	require.Equal(t, "vpn.example.com", c.Host)
	require.Equal(t, 443, c.Port)
	require.Equal(t, "tcp", c.Proto)
	require.True(t, c.NeedsAuth)
}

func TestParse_Defaults(t *testing.T) {
	c, err := Parse("remote 10.0.0.1\n")
	require.NoError(t, err)
	require.Equal(t, "10.0.0.1", c.Host)
	require.Equal(t, 1194, c.Port)
	require.Equal(t, "udp", c.Proto)
	require.Equal(t, 1, c.Remotes)
	require.False(t, c.HasIPv6)
}

func TestParse_RejectsUnsafeAndExternal(t *testing.T) {
	for _, line := range []string{
		"remote 1.2.3.4\nup /bin/sh\n",
		"remote 1.2.3.4\nscript-security 2\n",
		"remote 1.2.3.4\nplugin /tmp/evil.so\n",
		"remote 1.2.3.4\niproute /tmp/ip\n",
		"remote 1.2.3.4\nmanagement 127.0.0.1 7505\n",
	} {
		_, err := Parse(line)
		require.True(t, errors.Is(err, ErrUnsafe), "expected ErrUnsafe for %q, got %v", line, err)
	}

	for _, line := range []string{
		"remote 1.2.3.4\nca ca.crt\n",
		"remote 1.2.3.4\nauth-user-pass creds.txt\n",
		"remote 1.2.3.4\ntls-crypt ta.key\n",
	} {
		_, err := Parse(line)
		require.True(t, errors.Is(err, ErrExternal), "expected ErrExternal for %q, got %v", line, err)
	}
}

func TestParse_Errors(t *testing.T) {
	c, err := Parse("remote 10.0.0.1\ntun-ipv6\n")
	require.NoError(t, err)
	require.True(t, c.HasIPv6)

	_, err = Parse("dev tun\n")
	require.Error(t, err)

	_, err = Parse("remote 1.2.3.4\n<ca>\nCERT\n")
	require.Error(t, err)

	_, err = Parse("remote\n")
	require.Error(t, err)
}
