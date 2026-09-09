// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// isolateConfig points os.UserConfigDir (and the legacy XDG path) at a temp dir.
func isolateConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("AppData", dir) // windows
	return dir
}

// §AJ #23: these are PLAINTEXT content keys. They must live beside the rest of
// the CLI's state (os.UserConfigDir), not at the hand-built XDG/HOME path that
// credentials.go documents as a bug -- on Windows that is a different directory
// entirely, so the file was missed by anything cleaning up the real one.
func TestPendingResealLivesBesideTheCredential(t *testing.T) {
	isolateConfig(t)
	got, err := PendingResealPath()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := CredentialPath()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(got) != filepath.Dir(cred) {
		t.Fatalf("reseal store %q is not beside the credential %q", got, cred)
	}
}

// A store written by an older build at the old path is adopted and then removed,
// so the keys exist in one place only.
func TestPendingResealMigratesFromTheOldPath(t *testing.T) {
	dir := t.TempDir()
	// XDG set to one place, HOME to another, so the current path and the bare
	// ~/.config legacy path genuinely differ (as they always do on Windows).
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg"))
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("AppData", filepath.Join(dir, "appdata"))
	legacies := legacyPendingResealPaths()
	if len(legacies) == 0 {
		t.Skip("no distinct legacy path on this platform")
	}
	legacy := legacies[0]
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"pub-1":{"share_public_id":"pub-1","content_key":"a2V5","recipient_email":"r@example.test","created_at":"` +
		time.Now().UTC().Format(time.RFC3339) + `"}}`
	if err := os.WriteFile(legacy, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadPendingReseal()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store["pub-1"]; !ok {
		t.Fatalf("the old store was not adopted: %+v", store)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("the old file still holds plaintext keys after migration")
	}
}

// The TTL was enforced only when something happened to read the store, so an
// expired key could sit on disk indefinitely. A read must shorten the FILE.
func TestExpiredKeysAreRemovedFromDiskNotJustIgnored(t *testing.T) {
	isolateConfig(t)
	if err := RetainContentKey("pub-old", "a2V5", "r@example.test"); err != nil {
		t.Fatal(err)
	}
	path, _ := PendingResealPath()

	// Age the entry past the TTL.
	store, err := LoadPendingReseal()
	if err != nil {
		t.Fatal(err)
	}
	entry := store["pub-old"]
	entry.CreatedAt = time.Now().Add(-PendingResealTTL - time.Hour)
	store["pub-old"] = entry
	if err := SavePendingReseal(store); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadPendingReseal(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); contains(got, "pub-old") || contains(got, "a2V5") {
		t.Fatalf("an expired content key is still on disk: %s", got)
	}
}

// Logging out must take the keys with it: a leaked data key cannot be revoked.
func TestLogoutForgetsRetainedKeys(t *testing.T) {
	isolateConfig(t)
	if err := RetainContentKey("pub-1", "a2V5", "r@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := ForgetAllRetainedKeys(); err != nil {
		t.Fatal(err)
	}
	current, _ := PendingResealPath()
	for _, path := range append(legacyPendingResealPaths(), current) {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s survived logout", path)
		}
	}
	store, err := LoadPendingReseal()
	if err != nil || len(store) != 0 {
		t.Fatalf("store = %+v err = %v", store, err)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
