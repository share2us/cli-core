// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

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

// loadOrCreateIdentity reads this device's stable identity, creating it on
// first use.
//
// Three things used to go wrong quietly (§AJ low batch). A write error was
// discarded, so a device that could not save its key generated a NEW identity
// on every run -- it appeared as a different device each time, and every peer
// that had trusted it saw a stranger. The write also went through a plain
// WriteFile, which follows a symlink someone else planted at that path and
// truncates whatever is on the other end. And a file that already existed with
// loose permissions was left that way, because the mode in WriteFile applies
// only when it creates the file.
func loadOrCreateIdentity() (ed25519.PrivateKey, error) {
	dir, err := configDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "lan_identity.json")
	if data, err := os.ReadFile(path); err == nil {
		var f identityFile
		if json.Unmarshal(data, &f) == nil && len(f.Priv) == ed25519.PrivateKeySize {
			// Tighten an existing file that is more readable than it should be.
			if info, serr := os.Stat(path); serr == nil && info.Mode().Perm() != 0o600 {
				_ = os.Chmod(path, 0o600)
			}
			return ed25519.PrivateKey(f.Priv), nil
		}
	}
	_, priv, err := ed25519.GenerateKey(nil) // nil => crypto/rand
	if err != nil {
		return nil, err
	}
	if err := writeIdentity(path, priv); err != nil {
		// Report it: an identity that cannot be saved is a different device
		// tomorrow, which silently breaks every trust relationship it has.
		return nil, fmt.Errorf("lanid: could not save this device's identity to %s: %w", path, err)
	}
	return priv, nil
}

// writeIdentity writes the key through a fresh O_EXCL temp file and renames it
// into place: the temp cannot be a symlink someone else planted, and the rename
// is atomic, so a crash never leaves a half-written identity.
func writeIdentity(path string, priv ed25519.PrivateKey) error {
	data, err := json.Marshal(identityFile{Priv: priv})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".lan_identity-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op once the rename succeeds
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
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
