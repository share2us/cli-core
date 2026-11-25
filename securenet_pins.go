package clicore

// Trust on first use for Secure ShareNet account keys (owner decision 2026-11-25): the
// first account public key seen for an account is pinned; a different one later is a
// "key change" that this device won't wrap to or accept wraps from until the user trusts
// it (after comparing fingerprints). Earlier trusted keys stay trusted, so wraps made
// before a legitimate reset still open. The file also remembers which sharenets are
// Secure, so a server can't later claim one isn't and receive a plaintext post.
//
// The CLI and the daemon share the file: every change happens under a lock file, after
// re-reading it, so neither drops the other's pins.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// KeyChangedError names an account whose key differs from every key trusted for it.
type KeyChangedError struct {
	AccountID   string
	Fingerprint string
}

func (e *KeyChangedError) Error() string {
	return fmt.Sprintf("account %s has a NEW Secure ShareNet key (fingerprint %s). Compare it with them, then run 's2u keys trust %s %s'", e.AccountID, e.Fingerprint, e.AccountID, strings.ReplaceAll(e.Fingerprint, " ", ""))
}

// KeyUnknownError: an unattended run (the daemon) met a key it has never seen; first
// sight is only accepted interactively.
type KeyUnknownError struct{ AccountID string }

func (e *KeyUnknownError) Error() string {
	return fmt.Sprintf("account %s's key hasn't been seen on this device yet; run 's2u keys sync' once interactively", e.AccountID)
}

// KeyFingerprint is a safety number for an account key: 30 digits in six groups of five,
// from SHA-256("share2us/secure-sharenet/fingerprint/v1|" + accountID + "|" + pub). The
// portal computes the same.
func KeyFingerprint(accountID string, pub []byte) string {
	h := sha256.New()
	h.Write([]byte("share2us/secure-sharenet/fingerprint/v1|" + accountID + "|"))
	h.Write(pub)
	sum := h.Sum(nil)
	groups := make([]string, 6)
	for i := range groups {
		v := binary.BigEndian.Uint32(sum[i*4:i*4+4]) % 100000
		groups[i] = fmt.Sprintf("%05d", v)
	}
	return strings.Join(groups, " ")
}

// SameFingerprint compares a typed fingerprint with a computed one, ignoring spaces and
// dashes.
func SameFingerprint(typed, computed string) bool {
	norm := func(s string) string { return strings.Join(strings.Fields(strings.ReplaceAll(s, "-", " ")), "") }
	return norm(typed) != "" && norm(typed) == norm(computed)
}

type pinnedKey struct {
	PublicKey []byte    `json:"public_key"`
	TrustedAt time.Time `json:"trusted_at"`
}

type pinFile struct {
	Accounts map[string][]pinnedKey `json:"accounts"`
	Secure   map[string]time.Time   `json:"secure_sharenets,omitempty"`
}

// PinStore is the device's pin file (secure-sharenet-pins.json in the config directory).
type PinStore struct {
	path string
	mu   sync.Mutex
	data pinFile
}

func PinStorePath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "share2us", "secure-sharenet-pins.json"), nil
}

func OpenPinStore(path string) (*PinStore, error) {
	p := &PinStore{path: path}
	if err := p.reloadLocked(); err != nil {
		return nil, err
	}
	return p, nil
}

// reloadLocked reads the file (another process may have changed it). A damaged file is an
// error, never silently replaced: losing pins would turn the next key into a "first sight".
func (p *PinStore) reloadLocked() error {
	d := pinFile{}
	raw, err := os.ReadFile(p.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		if err := json.Unmarshal(raw, &d); err != nil {
			return fmt.Errorf("pin file %s is damaged (fix or move it aside): %w", p.path, err)
		}
	}
	if d.Accounts == nil {
		d.Accounts = map[string][]pinnedKey{}
	}
	if d.Secure == nil {
		d.Secure = map[string]time.Time{}
	}
	p.data = d
	return nil
}

func (p *PinStore) trustedLocked(accountID string, pub []byte) bool {
	for _, k := range p.data.Accounts[accountID] {
		if bytes.Equal(k.PublicKey, pub) {
			return true
		}
	}
	return false
}

func (p *PinStore) read(fn func()) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.reloadLocked(); err != nil {
		return err
	}
	fn()
	return nil
}

// IsTrusted reports whether pub is one of the keys trusted for accountID (never pins).
func (p *PinStore) IsTrusted(accountID string, pub []byte) (bool, error) {
	var ok bool
	err := p.read(func() { ok = p.trustedLocked(accountID, pub) })
	return ok, err
}

// Known reports whether any key is pinned for accountID.
func (p *PinStore) Known(accountID string) (bool, error) {
	var ok bool
	err := p.read(func() { ok = len(p.data.Accounts[accountID]) > 0 })
	return ok, err
}

// Check returns nil for a trusted key. A key for an account with no pin is pinned (first
// use) unless unattended, which returns *KeyUnknownError; any other key is a
// *KeyChangedError.
func (p *PinStore) Check(accountID string, pub []byte, unattended bool) error {
	return p.update(func() (bool, error) {
		if p.trustedLocked(accountID, pub) {
			return false, nil
		}
		if len(p.data.Accounts[accountID]) > 0 {
			return false, &KeyChangedError{AccountID: accountID, Fingerprint: KeyFingerprint(accountID, pub)}
		}
		if unattended {
			return false, &KeyUnknownError{AccountID: accountID}
		}
		p.data.Accounts[accountID] = []pinnedKey{{PublicKey: append([]byte(nil), pub...), TrustedAt: time.Now().UTC()}}
		return true, nil
	})
}

// Trust accepts pub for accountID (the user compared fingerprints, or this device made
// or recovered the key itself).
func (p *PinStore) Trust(accountID string, pub []byte) error {
	return p.update(func() (bool, error) {
		if p.trustedLocked(accountID, pub) {
			return false, nil
		}
		p.data.Accounts[accountID] = append(p.data.Accounts[accountID], pinnedKey{PublicKey: append([]byte(nil), pub...), TrustedAt: time.Now().UTC()})
		return true, nil
	})
}

// MarkSecure remembers that a sharenet is a Secure ShareNet (it can never stop being one).
func (p *PinStore) MarkSecure(sharenetID string) error {
	return p.update(func() (bool, error) {
		if _, ok := p.data.Secure[sharenetID]; ok {
			return false, nil
		}
		p.data.Secure[sharenetID] = time.Now().UTC()
		return true, nil
	})
}

func (p *PinStore) KnownSecure(sharenetID string) (bool, error) {
	var ok bool
	err := p.read(func() { _, ok = p.data.Secure[sharenetID] })
	return ok, err
}

// update runs fn on fresh data under the in-process mutex and the cross-process lock
// file, saving when fn reports a change.
func (p *PinStore) update(fn func() (bool, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	unlock, err := lockFile(p.path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	if err := p.reloadLocked(); err != nil {
		return err
	}
	changed, err := fn()
	if changed {
		if serr := p.saveLocked(); serr != nil {
			return serr
		}
	}
	return err
}

// lockFile is a portable advisory lock: create-exclusive, retried; a lock older than 30s
// is from a crashed process and is taken over.
func lockFile(path string) (func(), error) {
	const lockStale = 30 * time.Second
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if st, serr := os.Stat(path); serr == nil && time.Since(st.ModTime()) > lockStale {
			os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("pin file is locked by another process (%s)", path)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (p *PinStore) saveLocked() error {
	raw, err := json.MarshalIndent(p.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p.path), ".pins-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), p.path)
}
