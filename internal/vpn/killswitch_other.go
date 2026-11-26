//go:build !windows

package vpn

type killSwitch struct{}

func startKillSwitch(string) (*killSwitch, error) { return nil, nil }
func (k *killSwitch) Refresh() error              { return nil }
func (k *killSwitch) Close() error                { return nil }
