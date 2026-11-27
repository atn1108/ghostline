package vpn

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStore_AddListDelete(t *testing.T) {
	s := NewStore(t.TempDir())
	list, err := s.List()
	require.NoError(t, err)
	require.Empty(t, list)

	cfg := "dev tun\nproto tcp\nremote 219.100.37.104 443\n"
	p1, err := s.Add(`C:\tmp\vpngate_JP_219.100.37.104_tcp.ovpn`, cfg)
	require.NoError(t, err)
	require.Equal(t, "vpngate_JP_219.100.37.104_tcp", p1.Name)
	require.Equal(t, "219.100.37.104", p1.Host)
	require.Equal(t, 443, p1.Port)
	require.Equal(t, "tcp", p1.Proto)

	// Duplicate file name gets numbered cleanly.
	p2, err := s.Add("vpngate_JP_219.100.37.104_tcp.OVPN", cfg)
	require.NoError(t, err)
	require.Equal(t, "vpngate_JP_219.100.37.104_tcp (2)", p2.Name)

	path, err := s.ConfigPath(p1.ID)
	require.NoError(t, err)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, cfg, string(raw))

	// A stale .auth file is removed along with the profile.
	require.NoError(t, os.WriteFile(path+".auth", []byte("u\np\n"), 0o600))
	require.NoError(t, s.Delete(p1.ID))
	_, err = os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(path + ".auth")
	require.ErrorIs(t, err, os.ErrNotExist)

	list, err = s.List()
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, p2.ID, list[0].ID)
}

func TestStore_LimitsAndValidation(t *testing.T) {
	s := NewStore(t.TempDir())
	_, err := s.Add("big.ovpn", strings.Repeat("a", MaxConfigSize+1))
	require.Error(t, err)

	_, err = s.ConfigPath("../escape")
	require.Error(t, err)

	require.NoError(t, s.SetBinary("  /usr/sbin/openvpn  "))
	require.Equal(t, "/usr/sbin/openvpn", s.Binary())
	require.NoError(t, s.SetBinary(""))
	require.Equal(t, "", s.Binary())
}
