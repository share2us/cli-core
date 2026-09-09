// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Option B in-flight re-seal (docs/design/teammate-phase-c.md §2). When the CLI sends a
// teammate/device end-to-end share it seals the content key to each recipient device and,
// today, forgets it. To recover a share whose recipient re-keys before pulling, the sender
// must be able to re-seal the SAME content key to the recipient's new device key. This store
// retains those content keys locally (0600, beside credentials.json) until the share is
// delivered (acked) or a TTL elapses, then prunes them.
//
// Security note: this is a NEW persisted secret on the sender — plaintext content keys (DEKs)
// at rest. It is bounded (0600 file, pruned aggressively, only for teammate/device sends —
// never for link/URL-fragment shares) and never leaves the machine. See the ADR/plan security
// call-out. The server still never sees a key.

const PendingResealTTL = 14 * 24 * time.Hour

type PendingResealEntry struct {
	SharePublicID  string    `json:"share_public_id"`
	ContentKey     string    `json:"content_key"` // base64 of the 32-byte AES-256-GCM data key
	RecipientEmail string    `json:"recipient_email"`
	CreatedAt      time.Time `json:"created_at"`
}

// PendingResealStore maps a share's public id to its retained content key.
type PendingResealStore map[string]PendingResealEntry

// PendingResealPath sits beside credentials.json, via os.UserConfigDir.
//
// It used to build the path from XDG_CONFIG_HOME/HOME directly, which is the
// bug credentials.go documents: on Windows that is %USERPROFILE%\.config, not
// %AppData%\Roaming, so this file -- plaintext content keys -- was written to a
// different, less expected directory than every other piece of CLI state, and
// was missed by anything that cleaned up the real one (§AJ #23). A file left at
// the old path is migrated on first use and removed.
func PendingResealPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "share2us", "pending_reseal.json"), nil
}

// legacyPendingResealPaths lists every place an older build may have left the
// store: the XDG_CONFIG_HOME-derived path and the bare ~/.config one. On Windows
// the second is %USERPROFILE%\.config, which is the divergence that mattered;
// on Linux they differ whenever XDG_CONFIG_HOME is set. The current path is
// never included.
func legacyPendingResealPaths() []string {
	current, _ := PendingResealPath()
	var out []string
	add := func(base string) {
		if base == "" {
			return
		}
		p := filepath.Join(base, "share2us", "pending_reseal.json")
		if p == current {
			return
		}
		for _, seen := range out {
			if seen == p {
				return
			}
		}
		out = append(out, p)
	}
	add(os.Getenv("XDG_CONFIG_HOME"))
	if home, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(home, ".config"))
	}
	return out
}

// ForgetAllRetainedKeys deletes the whole store. Called at logout: these are
// plaintext data keys for shares this login sent, and a key that cannot be
// revoked must not outlive the session that created it (§AJ #23).
func ForgetAllRetainedKeys() error {
	var firstErr error
	current, err := PendingResealPath()
	if err != nil {
		firstErr = err
	}
	paths := legacyPendingResealPaths()
	if current != "" {
		paths = append(paths, current)
	}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// LoadPendingReseal reads the retained-key store, returning an empty (non-nil) store when the
// file does not exist yet. TTL-expired entries are dropped on read.
func LoadPendingReseal() (PendingResealStore, error) {
	path, err := PendingResealPath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		// Adopt a store left at a pre-fix path, then remove it so the keys exist
		// in one place only (§AJ #23).
		adopted := false
		for _, legacy := range legacyPendingResealPaths() {
			if data, lerr := os.ReadFile(legacy); lerr == nil {
				raw = data
				defer os.Remove(legacy)
				adopted = true
				break
			}
		}
		if !adopted {
			return PendingResealStore{}, nil
		}
	}
	var store PendingResealStore
	if err := json.Unmarshal(raw, &store); err != nil {
		return nil, fmt.Errorf("parse pending reseal store: %w", err)
	}
	if store == nil {
		store = PendingResealStore{}
	}
	// Expiry is enforced on READ, so an entry could sit on disk past its TTL
	// until something happened to load the store. Write the pruned store back so
	// the key is actually gone from the file, not merely ignored (§AJ #23).
	if store.pruneExpired(time.Now()) {
		_ = SavePendingReseal(store)
	}
	return store, nil
}

func SavePendingReseal(store PendingResealStore) error {
	path, err := PendingResealPath()
	if err != nil {
		return err
	}
	if store == nil {
		store = PendingResealStore{}
	}
	raw, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// RetainContentKey records a content key so the share can be re-sealed later. A best-effort
// helper: a store error is returned but callers may choose to warn-and-continue rather than
// fail the send (retention is a recovery aid, not core to delivery).
func RetainContentKey(sharePublicID, contentKeyB64, recipientEmail string) error {
	if sharePublicID == "" || contentKeyB64 == "" {
		return nil
	}
	store, err := LoadPendingReseal()
	if err != nil {
		return err
	}
	store[sharePublicID] = PendingResealEntry{
		SharePublicID:  sharePublicID,
		ContentKey:     contentKeyB64,
		RecipientEmail: recipientEmail,
		CreatedAt:      time.Now().UTC(),
	}
	return SavePendingReseal(store)
}

// ForgetRetainedKey drops a retained content key once its share has been delivered.
func ForgetRetainedKey(sharePublicID string) error {
	store, err := LoadPendingReseal()
	if err != nil {
		return err
	}
	if _, ok := store[sharePublicID]; !ok {
		return nil
	}
	delete(store, sharePublicID)
	return SavePendingReseal(store)
}

// pruneExpired drops entries past the TTL and reports whether it removed any,
// so the caller can write the shortened store back to disk (§AJ #23).
func (s PendingResealStore) pruneExpired(now time.Time) bool {
	removed := false
	for id, entry := range s {
		if now.Sub(entry.CreatedAt) > PendingResealTTL {
			delete(s, id)
			removed = true
		}
	}
	return removed
}
