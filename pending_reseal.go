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

func PendingResealPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "share2us", "pending_reseal.json"), nil
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
		if errors.Is(err, os.ErrNotExist) {
			return PendingResealStore{}, nil
		}
		return nil, err
	}
	var store PendingResealStore
	if err := json.Unmarshal(raw, &store); err != nil {
		return nil, fmt.Errorf("parse pending reseal store: %w", err)
	}
	if store == nil {
		store = PendingResealStore{}
	}
	store.pruneExpired(time.Now())
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

func (s PendingResealStore) pruneExpired(now time.Time) {
	for id, entry := range s {
		if now.Sub(entry.CreatedAt) > PendingResealTTL {
			delete(s, id)
		}
	}
}
