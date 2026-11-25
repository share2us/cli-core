package clicore

// Trust on first use for Secure ShareNet account keys (owner decision 2026-11-25): the
// first account public key seen for an account is pinned; a different one later is a
// "key change" that this device won't wrap to or accept wraps from until the user trusts
// it (after comparing fingerprints). Earlier trusted keys stay trusted, so wraps made
// before a legitimate reset still open.

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
	return fmt.Sprintf("account %s has a NEW Secure ShareNet key (fingerprint %s). Compare it with them, then run 's2u keys trust %s'", e.AccountID, e.Fingerprint, e.AccountID)
}

// KeyFingerprint is a safety number for an account key: 30 digits in six groups of five,
// from SHA-256("share2us/secure-sharenet/fingerprint/v1" || accountID || pub). The portal
// computes the same.
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

type pinnedKey struct {
	PublicKey []byte    `json:"public_key"`
	TrustedAt time.Time `json:"trusted_at"`
}

type pinFile struct {
	Accounts map[string][]pinnedKey `json:"accounts"`
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
	p := &PinStore{path: path, data: pinFile{Accounts: map[string][]pinnedKey{}}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &p.data); err != nil {
		return nil, fmt.Errorf("pin file %s is damaged: %w", path, err)
	}
	if p.data.Accounts == nil {
		p.data.Accounts = map[string][]pinnedKey{}
	}
	return p, nil
}

// Check pins pub on first sight and returns nil; a key that matches one already trusted
// is nil; any other key is a *KeyChangedError.
func (p *PinStore) Check(accountID string, pub []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reloadLocked()
	keys := p.data.Accounts[accountID]
	for _, k := range keys {
		if bytes.Equal(k.PublicKey, pub) {
			return nil
		}
	}
	if len(keys) > 0 {
		return &KeyChangedError{AccountID: accountID, Fingerprint: KeyFingerprint(accountID, pub)}
	}
	p.data.Accounts[accountID] = []pinnedKey{{PublicKey: append([]byte(nil), pub...), TrustedAt: time.Now().UTC()}}
	return p.saveLocked()
}

// Trust accepts pub for accountID (the user compared fingerprints).
func (p *PinStore) Trust(accountID string, pub []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reloadLocked()
	for _, k := range p.data.Accounts[accountID] {
		if bytes.Equal(k.PublicKey, pub) {
			return nil
		}
	}
	p.data.Accounts[accountID] = append(p.data.Accounts[accountID], pinnedKey{PublicKey: append([]byte(nil), pub...), TrustedAt: time.Now().UTC()})
	return p.saveLocked()
}

// Pinned reports the most recently trusted key for accountID, if any.
func (p *PinStore) Pinned(accountID string) ([]byte, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	keys := p.data.Accounts[accountID]
	if len(keys) == 0 {
		return nil, false
	}
	return keys[len(keys)-1].PublicKey, true
}

// reloadLocked picks up pins another process (the CLI or the daemon) wrote meanwhile.
func (p *PinStore) reloadLocked() {
	raw, err := os.ReadFile(p.path)
	if err != nil {
		return
	}
	var d pinFile
	if json.Unmarshal(raw, &d) == nil && d.Accounts != nil {
		p.data = d
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
