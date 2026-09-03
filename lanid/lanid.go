// Package lanid manages this device's persistent LAN identity (an Ed25519
// keypair) and the trusted-devices store, shared by the `s2u` CLI and the
// desktop GUI. Both store under os.UserConfigDir()/share2us (the same base
// cli-core uses for credentials/config), so a device's identity and the devices
// it trusts are shared across the CLI and GUI on one machine.
//
// Trust is keyed by the peer's verified public-key fingerprint (never its name
// or IP), so a device recognised once needs no per-transfer verify code — and
// can be revoked.
package lanid

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/share2us/cli-core/lanshare"
)

// configDir returns os.UserConfigDir()/share2us (the same base cli-core uses for
// credentials/config), creating it 0700 if needed.
func configDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "share2us")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// ---- device identity --------------------------------------------------------

type identityFile struct {
	Priv []byte `json:"priv"` // ed25519 private key (64 bytes)
}

var (
	idOnce sync.Once
	idKey  ed25519.PrivateKey
	idErr  error
)

// Identity returns this device's persistent Ed25519 identity, creating and
// saving it (0600) on first use.
func Identity() (ed25519.PrivateKey, error) {
	idOnce.Do(func() { idKey, idErr = loadOrCreateIdentity() })
	return idKey, idErr
}

func loadOrCreateIdentity() (ed25519.PrivateKey, error) {
	dir, err := configDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "lan_identity.json")
	if data, err := os.ReadFile(path); err == nil {
		var f identityFile
		if json.Unmarshal(data, &f) == nil && len(f.Priv) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(f.Priv), nil
		}
	}
	_, priv, err := ed25519.GenerateKey(nil) // nil => crypto/rand
	if err != nil {
		return nil, err
	}
	if data, merr := json.Marshal(identityFile{Priv: priv}); merr == nil {
		_ = os.WriteFile(path, data, 0o600)
	}
	return priv, nil
}

// Fingerprint / Code identify this device to peers.
func Fingerprint() string {
	k, err := Identity()
	if err != nil {
		return ""
	}
	return lanshare.IdentityFingerprint(k.Public().(ed25519.PublicKey))
}

// Code is the short human-verifiable code for this device's fingerprint.
func Code() string { return lanshare.VerifyCode(Fingerprint()) }

// ---- trusted-devices store --------------------------------------------------

// TrustedDevice is a device we've trusted, keyed by its verified Ed25519 key
// fingerprint. Trust skips the verify-code compare and the anti-spam caps; what
// happens next depends on Mode: ModeAsk (the default) still asks the receiver to
// approve each transfer, ModeAuto lets its transfers land without a prompt.
// Untrusted devices always go through the full prompt. Revocable.
type TrustedDevice struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	// Mode is ModeAsk or ModeAuto. Empty (records written before modes existed)
	// means ModeAsk: the safer reading, never fewer prompts than the user expects.
	Mode string `json:"mode,omitempty"`
}

// Trust modes.
const (
	// ModeAsk: trusted, but every transfer still needs a one-tap approval (no
	// verify code, no anti-spam caps). The default.
	ModeAsk = "ask"
	// ModeAuto: trusted and its transfers are saved without asking.
	ModeAuto = "auto"
)

// NormalizeMode maps user input to a mode constant ("" -> ModeAsk).
func NormalizeMode(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", ModeAsk:
		return ModeAsk, nil
	case ModeAuto:
		return ModeAuto, nil
	default:
		return "", fmt.Errorf("unknown trust mode %q (ask or auto)", v)
	}
}

// EffectiveMode returns the device's mode with the legacy empty value read as ask.
func (d TrustedDevice) EffectiveMode() string {
	if d.Mode == ModeAuto {
		return ModeAuto
	}
	return ModeAsk
}

// AutoAccept reports whether transfers from this device may land without asking.
func (d TrustedDevice) AutoAccept() bool { return d.EffectiveMode() == ModeAuto }

type trustStore struct {
	mu   sync.Mutex
	path string
	m    map[string]TrustedDevice
}

var (
	tsOnce sync.Once
	ts     *trustStore
	tsErr  error
)

func store() (*trustStore, error) {
	tsOnce.Do(func() {
		dir, err := configDir()
		if err != nil {
			tsErr = err
			return
		}
		s := &trustStore{path: filepath.Join(dir, "lan_trusted.json"), m: map[string]TrustedDevice{}}
		if data, rerr := os.ReadFile(s.path); rerr == nil {
			var list []TrustedDevice
			if json.Unmarshal(data, &list) == nil {
				for _, d := range list {
					if d.Fingerprint != "" {
						s.m[d.Fingerprint] = d
					}
				}
			}
		}
		ts = s
	})
	return ts, tsErr
}

// saveLocked writes the store atomically (caller holds s.mu).
func (s *trustStore) saveLocked() {
	list := make([]TrustedDevice, 0, len(s.m))
	for _, d := range s.m {
		list = append(list, d)
	}
	if data, err := json.MarshalIndent(list, "", "  "); err == nil {
		tmp := s.path + ".tmp"
		if os.WriteFile(tmp, data, 0o600) == nil {
			_ = os.Rename(tmp, s.path)
		}
	}
}

// Lookup returns the trusted device for a fingerprint (ok=false if untrusted or
// the fingerprint is empty/anonymous).
func Lookup(fingerprint string) (TrustedDevice, bool) {
	if fingerprint == "" {
		return TrustedDevice{}, false
	}
	s, err := store()
	if err != nil {
		return TrustedDevice{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.m[fingerprint]
	return d, ok
}

// Trust adds/updates a trusted device in the default ModeAsk (revocable). An
// existing record keeps its mode; use TrustWithMode or SetMode to change it.
func Trust(fingerprint, name string) error {
	return trust(fingerprint, name, "", false)
}

// TrustWithMode adds/updates a trusted device with an explicit mode.
func TrustWithMode(fingerprint, name, mode string) error {
	m, err := NormalizeMode(mode)
	if err != nil {
		return err
	}
	return trust(fingerprint, name, m, true)
}

func trust(fingerprint, name, mode string, setMode bool) error {
	if fingerprint == "" {
		return nil
	}
	s, err := store()
	if err != nil {
		return err
	}
	s.mu.Lock()
	d := TrustedDevice{Fingerprint: fingerprint, Name: name}
	if prev, ok := s.m[fingerprint]; ok && !setMode {
		d.Mode = prev.Mode
	}
	if setMode {
		d.Mode = mode
	}
	if d.Mode == ModeAsk {
		d.Mode = "" // ask is the default; keep the file minimal
	}
	s.m[fingerprint] = d
	s.saveLocked()
	s.mu.Unlock()
	return nil
}

// SetMode changes the mode of an already-trusted device.
func SetMode(fingerprint, mode string) error {
	m, err := NormalizeMode(mode)
	if err != nil {
		return err
	}
	s, err := store()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.m[fingerprint]
	if !ok {
		return fmt.Errorf("device %s is not trusted", fingerprint)
	}
	if m == ModeAsk {
		d.Mode = ""
	} else {
		d.Mode = m
	}
	s.m[fingerprint] = d
	s.saveLocked()
	return nil
}

// Untrust removes a device from the trust store (revoke).
func Untrust(fingerprint string) error {
	s, err := store()
	if err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.m, fingerprint)
	s.saveLocked()
	s.mu.Unlock()
	return nil
}

// List returns the trusted devices, sorted by name.
func List() []TrustedDevice {
	s, err := store()
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]TrustedDevice, 0, len(s.m))
	for _, d := range s.m {
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}
