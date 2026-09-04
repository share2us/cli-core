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
	"time"

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

// SafetyNumber is this device's long comparison number (lanshare.SafetyNumber),
// shown at trust time next to the 6-digit Code.
func SafetyNumber() string { return lanshare.SafetyNumber(Fingerprint()) }

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

// Lookup returns the trusted device for a fingerprint from the VERIFIED server-
// signed cache (ok=false if untrusted, anonymous, or no valid cache).
func Lookup(fingerprint string) (TrustedDevice, bool) {
	if fingerprint == "" {
		return TrustedDevice{}, false
	}
	for _, d := range cachedDevices(time.Now()) {
		if d.Fingerprint == fingerprint {
			return d, true
		}
	}
	return TrustedDevice{}, false
}

// List returns the trusted devices from the verified cache, sorted by name.
func List() []TrustedDevice {
	list := cachedDevices(time.Now())
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

// Trust, TrustWithMode, SetMode and Untrust were the local writers of the
// pre-ADR-034 trust file. Trust is now granted, changed and revoked through the
// account API (with MFA for anything that widens it); these remain only so old
// callers fail loudly instead of silently writing a file nobody reads.
func Trust(string, string) error                 { return ErrLocalTrustDisabled }
func TrustWithMode(string, string, string) error { return ErrLocalTrustDisabled }
func SetMode(string, string) error               { return ErrLocalTrustDisabled }
func Untrust(string) error                       { return ErrLocalTrustDisabled }

// RemoveLegacyTrustFile deletes the pre-ADR-034 local trust file if present. Its
// entries were never verified by a second factor, so they are not migrated; the
// user re-trusts each device with MFA. Best-effort.
func RemoveLegacyTrustFile() {
	dir, err := configDir()
	if err != nil {
		return
	}
	_ = os.Remove(filepath.Join(dir, "lan_trusted.json"))
}
