package app

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/hashcott/ghostline/internal/vpn"
)

// VPNProfile is one imported .ovpn file, as the VPN page shows it.
type VPNProfile struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Proto     string `json:"proto"`
	Dev       string `json:"dev"`
	Remotes   int    `json:"remotes"`
	NeedsAuth bool   `json:"needsAuth"`
	Created   int64  `json:"created"` // unix milliseconds
}

// VPNStatus is the OpenVPN client's state.
type VPNStatus struct {
	Phase     string   `json:"phase"` // idle | starting | connected | error
	ProfileID string   `json:"profileId"`
	Since     int64    `json:"since"` // unix milliseconds; 0 unless connected
	Error     string   `json:"error"`
	Log       []string `json:"log"`
}

// VPNInfo is everything the VPN page shows.
type VPNInfo struct {
	// Supported is false where the platform wires no OpenVPN support.
	Supported bool         `json:"supported"`
	Binary    string       `json:"binary"`   // openvpn in use, "" when not found
	Detected  string       `json:"detected"` // what auto-detection finds
	Profiles  []VPNProfile `json:"profiles"`
	Status    VPNStatus    `json:"status"`
}

// VPNInfo returns the OpenVPN path in use, the imported profiles and the
// tunnel state.
func (s *Service) VPNInfo() VPNInfo {
	info := VPNInfo{
		Profiles: []VPNProfile{},
		Status:   VPNStatus{Phase: vpn.PhaseIdle, Log: []string{}},
	}
	if s.x.VPNStore == nil || s.x.VPN == nil {
		return info
	}
	info.Supported = true
	if list, err := s.x.VPNStore.List(); err != nil {
		slog.Warn("vpn: listing profiles", "err", err)
	} else {
		for _, p := range list {
			info.Profiles = append(info.Profiles, vpnProfile(p))
		}
	}
	info.Detected = vpn.Detect("")
	info.Binary = vpn.Detect(s.x.VPNStore.Binary())
	info.Status = vpnStatus(s.x.VPN.Status())
	return info
}

// VPNAdd keeps an .ovpn file the page read: the window reads the file the
// user picked, Ghostline only receives its text.
func (s *Service) VPNAdd(name, config string) (VPNProfile, error) {
	if s.x.VPNStore == nil {
		return VPNProfile{}, appErr(CodeVPNUnsupported, nil)
	}
	if strings.TrimSpace(config) == "" {
		return VPNProfile{}, appErr(CodeVPNBadConfig, errors.New("the file is empty"))
	}
	p, err := s.x.VPNStore.Add(name, config)
	if err != nil {
		return VPNProfile{}, vpnErr(err)
	}
	return vpnProfile(p), nil
}

// VPNDelete removes a profile; a running tunnel on it is stopped first.
func (s *Service) VPNDelete(id string) error {
	if s.x.VPNStore == nil {
		return appErr(CodeVPNUnsupported, nil)
	}
	if s.x.VPN != nil && s.x.VPN.Status().ProfileID == id {
		s.x.VPN.Stop()
	}
	if err := s.x.VPNStore.Delete(id); err != nil {
		return vpnErr(err)
	}
	if s.x.VPN != nil {
		s.x.VPN.ClearIfProfile(id)
	}
	return nil
}

// VPNConnect starts openvpn on a profile. user and pass are used only by
// profiles that ask for them and are never stored.
func (s *Service) VPNConnect(id, user, pass string) error {
	if s.x.VPNStore == nil || s.x.VPN == nil {
		return appErr(CodeVPNUnsupported, nil)
	}
	binary := vpn.Detect(s.x.VPNStore.Binary())
	if binary == "" {
		return appErr(CodeVPNBinaryMissing, nil)
	}
	profiles, err := s.x.VPNStore.List()
	if err != nil {
		return vpnErr(err)
	}
	var p *vpn.Profile
	for i := range profiles {
		if profiles[i].ID == id {
			p = &profiles[i]
			break
		}
	}
	if p == nil {
		return appErr(CodeVPNBadConfig, fmt.Errorf("no profile %q", id))
	}
	if p.NeedsAuth && user == "" {
		return appErr(CodeVPNNeedsAuth, nil)
	}
	path, err := s.x.VPNStore.ConfigPath(id)
	if err != nil {
		return vpnErr(err)
	}
	opts := vpn.StartOptions{
		BlockIPv6:    !p.HasIPv6,
		KeepLocalDNS: s.x.DNSActive != nil && s.x.DNSActive(),
	}
	if err := s.x.VPN.Start(binary, id, path, user, pass, opts); err != nil {
		return appErr(CodeVPNStartFailed, err)
	}
	return nil
}

// VPNDisconnect stops the tunnel.
func (s *Service) VPNDisconnect() {
	if s.x.VPN != nil {
		s.x.VPN.Stop()
	}
}

// VPNSetBinary picks the openvpn executable; "" goes back to auto-detection.
func (s *Service) VPNSetBinary(path string) error {
	if s.x.VPNStore == nil {
		return appErr(CodeVPNUnsupported, nil)
	}
	path = strings.TrimSpace(path)
	if path != "" {
		st, err := os.Stat(path)
		if err != nil {
			return appErr(CodeVPNBinaryMissing, err)
		}
		if st.IsDir() {
			return appErr(CodeVPNBinaryMissing, errors.New("that is a folder, not openvpn"))
		}
	}
	if err := s.x.VPNStore.SetBinary(path); err != nil {
		return vpnErr(err)
	}
	return nil
}

// VPNDetectBinary returns the openvpn found on this computer ("" if none).
func (s *Service) VPNDetectBinary() string { return vpn.Detect("") }

// VPNStatusEvent converts the runner's state into the shape the VPN page
// and the vpn:status event both use.
func VPNStatusEvent(st vpn.Status) VPNStatus { return vpnStatus(st) }

func vpnProfile(p vpn.Profile) VPNProfile {
	return VPNProfile{
		ID:        p.ID,
		Name:      p.Name,
		Host:      p.Host,
		Port:      p.Port,
		Proto:     p.Proto,
		Dev:       p.Dev,
		Remotes:   p.Remotes,
		NeedsAuth: p.NeedsAuth,
		Created:   p.Created,
	}
}

func vpnStatus(st vpn.Status) VPNStatus {
	out := VPNStatus{
		Phase:     st.Phase,
		ProfileID: st.ProfileID,
		Since:     st.Since,
		Error:     st.Error,
		Log:       st.Log,
	}
	if out.Log == nil {
		out.Log = []string{}
	}
	if out.Phase == "" {
		out.Phase = vpn.PhaseIdle
	}
	return out
}

// vpnErr turns the profile store's errors into the codes the UI translates.
func vpnErr(err error) error {
	switch {
	case errors.Is(err, vpn.ErrUnsafe):
		return appErr(CodeVPNUnsafe, err)
	case errors.Is(err, vpn.ErrExternal):
		return appErr(CodeVPNExternal, err)
	}
	return appErr(CodeVPNBadConfig, err)
}
