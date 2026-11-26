package vpn

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hashcott/ghostline/internal/store"
)

// MaxProfiles caps how many .ovpn files the page keeps.
const MaxProfiles = 50

// MaxConfigSize caps one .ovpn file: inline certificates keep it small.
const MaxConfigSize = 1 << 20

// Profile is one imported OpenVPN configuration.
type Profile struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Proto     string `json:"proto"`
	Dev       string `json:"dev"`
	Remotes   int    `json:"remotes"`
	HasIPv6   bool   `json:"hasIpv6,omitempty"`
	NeedsAuth bool   `json:"needsAuth"`
	Created   int64  `json:"created"` // unix milliseconds
}

// profilesFile is vpn.json: the chosen openvpn path and every profile.
type profilesFile struct {
	Binary   string    `json:"binary,omitempty"`
	Profiles []Profile `json:"profiles"`
}

// Store keeps the profile list in <dataDir>/vpn.json and each config as its
// own file under <dataDir>/vpn.
type Store struct {
	dir  string
	path string
}

// NewStore returns the profile store for a data directory.
func NewStore(dataDir string) *Store {
	return &Store{dir: filepath.Join(dataDir, "vpn"), path: filepath.Join(dataDir, "vpn.json")}
}

var profileID = regexp.MustCompile(`^[0-9a-f]{16}$`)

func (s *Store) load() (profilesFile, error) {
	var f profilesFile
	err := store.ReadJSON(s.path, &f)
	if errors.Is(err, fs.ErrNotExist) {
		return profilesFile{}, nil
	}
	if err != nil {
		return profilesFile{}, fmt.Errorf("vpn: reading the profile list: %w", err)
	}
	return f, nil
}

func (s *Store) save(f profilesFile) error {
	if f.Profiles == nil {
		f.Profiles = []Profile{}
	}
	if err := store.WriteJSONAtomic(s.path, f); err != nil {
		return fmt.Errorf("vpn: saving the profile list: %w", err)
	}
	return nil
}

// List returns the imported profiles, newest last.
func (s *Store) List() ([]Profile, error) {
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	if f.Profiles == nil {
		f.Profiles = []Profile{}
	}
	return f.Profiles, nil
}

// Binary returns the openvpn path the user chose ("" means auto-detect).
func (s *Store) Binary() string {
	f, err := s.load()
	if err != nil {
		return ""
	}
	return f.Binary
}

// SetBinary remembers the openvpn path; "" goes back to auto-detection.
func (s *Store) SetBinary(path string) error {
	f, err := s.load()
	if err != nil {
		return err
	}
	f.Binary = strings.TrimSpace(path)
	return s.save(f)
}

// Add validates an .ovpn file, stores it under name and returns its profile.
func (s *Store) Add(name, text string) (Profile, error) {
	if len(text) > MaxConfigSize {
		return Profile{}, fmt.Errorf("vpn: the profile is larger than 1 MB")
	}
	cfg, err := Parse(text)
	if err != nil {
		return Profile{}, err
	}
	f, err := s.load()
	if err != nil {
		return Profile{}, err
	}
	if len(f.Profiles) >= MaxProfiles {
		return Profile{}, fmt.Errorf("vpn: at most %d profiles", MaxProfiles)
	}
	id, err := newID()
	if err != nil {
		return Profile{}, err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return Profile{}, fmt.Errorf("vpn: creating the profile folder: %w", err)
	}
	p := Profile{
		ID:        id,
		Name:      uniqueName(profileName(name, cfg.Host), f.Profiles),
		Host:      cfg.Host,
		Port:      cfg.Port,
		Proto:     cfg.Proto,
		Dev:       cfg.Dev,
		Remotes:   cfg.Remotes,
		HasIPv6:   cfg.HasIPv6,
		NeedsAuth: cfg.NeedsAuth,
		Created:   time.Now().UnixMilli(),
	}
	path := s.configPath(id)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return Profile{}, fmt.Errorf("vpn: saving the profile: %w", err)
	}
	f.Profiles = append(f.Profiles, p)
	if err := s.save(f); err != nil {
		_ = os.Remove(path)
		return Profile{}, err
	}
	return p, nil
}

// Delete removes a profile and its config file.
func (s *Store) Delete(id string) error {
	f, err := s.load()
	if err != nil {
		return err
	}
	i := -1
	for j, p := range f.Profiles {
		if p.ID == id {
			i = j
			break
		}
	}
	if i < 0 {
		return fmt.Errorf("vpn: no profile %q", id)
	}
	f.Profiles = append(f.Profiles[:i], f.Profiles[i+1:]...)
	if err := s.save(f); err != nil {
		return err
	}
	_ = os.Remove(s.configPath(id) + ".auth")
	if err := os.Remove(s.configPath(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("vpn: deleting the profile file: %w", err)
	}
	return nil
}

// ConfigPath returns the stored config file of a profile.
func (s *Store) ConfigPath(id string) (string, error) {
	if !profileID.MatchString(id) {
		return "", fmt.Errorf("vpn: bad profile id")
	}
	path := s.configPath(id)
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("vpn: profile %q is gone", id)
	}
	return path, nil
}

func (s *Store) configPath(id string) string { return filepath.Join(s.dir, id+".ovpn") }

func newID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// profileName turns a picked file name into a profile name.
func profileName(name, host string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".ovpn"), ".OVPN")
	name = strings.Map(func(r rune) rune {
		if r < 0x20 {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" {
		name = host
	}
	if len(name) > 80 {
		name = name[:80]
	}
	return name
}

func uniqueName(name string, have []Profile) string {
	taken := func(n string) bool {
		for _, p := range have {
			if p.Name == n {
				return true
			}
		}
		return false
	}
	if !taken(name) {
		return name
	}
	for i := 2; ; i++ {
		if n := fmt.Sprintf("%s (%d)", name, i); !taken(n) {
			return n
		}
	}
}
