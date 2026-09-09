// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanid

import (
	"os"
	"testing"

	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"time"
)

// TestMain points os.UserConfigDir at a temp dir so the package's identity /
// trust / settings / activity files are written under the test's HOME, not the
// developer's real config. (os.UserConfigDir uses XDG_CONFIG_HOME on Linux and
// HOME elsewhere.)
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "lanid-test-*")
	if err != nil {
		panic(err)
	}
	os.Setenv("XDG_CONFIG_HOME", dir)
	os.Setenv("HOME", dir)
	os.Setenv("AppData", dir) // windows
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func TestIdentityStableAndFingerprinted(t *testing.T) {
	k1, err := Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	k2, _ := Identity()
	if string(k1) != string(k2) {
		t.Fatal("Identity not stable across calls")
	}
	if Fingerprint() == "" {
		t.Fatal("empty fingerprint")
	}
	if Code() == "" {
		t.Fatal("empty verify code")
	}
}

func TestScanIntervalAndActivity(t *testing.T) {
	if GetScanInterval() != defaultScanIntervalSec {
		t.Fatalf("default scan interval = %d", GetScanInterval())
	}
	if err := SetScanInterval(5); err != nil {
		t.Fatalf("SetScanInterval: %v", err)
	}
	if GetScanInterval() != 5 {
		t.Fatalf("scan interval not persisted = %d", GetScanInterval())
	}

	ActivityClear()
	ActivityAppend(ActivityEntry{Kind: "broadcast", Peer: "p1", Name: "a.txt", Size: 10})
	ActivityAppend(ActivityEntry{Kind: "downloaded", Peer: "p2", Name: "b.txt", Size: 20})
	list := ActivityList()
	if len(list) != 2 || list[0].Kind != "downloaded" { // newest first
		t.Fatalf("ActivityList = %+v", list)
	}
	if list[0].TS == 0 {
		t.Fatal("activity timestamp not set")
	}
	ActivityClear()
	if len(ActivityList()) != 0 {
		t.Fatal("activity not cleared")
	}
}

// signTestList mimics the server: an Ed25519-signed payload for the given devices.
func signTestList(t *testing.T, priv ed25519.PrivateKey, devices []TrustedDevice, exp time.Time) SignedTrustList {
	t.Helper()
	raw, err := json.Marshal(TrustListPayload{Version: 1, AccountID: "acct", IssuedAt: exp.Add(-ListTTLForTests), ExpiresAt: exp, Devices: devices})
	if err != nil {
		t.Fatal(err)
	}
	return SignedTrustList{KeyID: "test", Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, raw))}
}

const ListTTLForTests = 24 * time.Hour

// bindTestAccount makes the cache readable for account "acct" (the one
// signTestList issues for) and pins the given server keys through the env
// override, the way a self-hosted server would.
func bindTestAccount(t *testing.T, pubHexes ...string) {
	t.Helper()
	prev := CurrentAccountID
	CurrentAccountID = func() string { return "acct" }
	t.Cleanup(func() { CurrentAccountID = prev })
	t.Setenv(TrustKeysEnv, strings.Join(pubHexes, ","))
}

func TestSignedTrustCacheIsTheOnlySourceOfTrust(t *testing.T) {
	t.Cleanup(func() { _ = ResetTrust() })
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubHex := hex.EncodeToString(pub)
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	bindTestAccount(t, pubHex, hex.EncodeToString(pub2))
	const fp = "b676f58a180a7fc204ab3a1c0d24eb9eec33b66faa066569eef3fa0d8096d37c"

	// Nothing cached: nothing trusted; local writers are retired.
	if _, ok := Lookup(fp); ok {
		t.Fatal("trusted with no cache")
	}
	if err := Trust(fp, "x"); !errors.Is(err, ErrLocalTrustDisabled) {
		t.Fatalf("Trust must be disabled, got %v", err)
	}
	if err := SetMode(fp, ModeAuto); !errors.Is(err, ErrLocalTrustDisabled) {
		t.Fatalf("SetMode must be disabled, got %v", err)
	}

	// A valid signed list makes the device trusted with its mode.
	list := signTestList(t, priv, []TrustedDevice{{Fingerprint: fp, Name: "laptop", Mode: ModeAuto}}, time.Now().Add(time.Hour))
	if err := SaveSignedTrust(list, pubHex); err != nil {
		t.Fatal(err)
	}
	d, ok := Lookup(fp)
	if !ok || !d.AutoAccept() || d.Name != "laptop" {
		t.Fatalf("lookup = %+v ok=%v", d, ok)
	}
	if got := List(); len(got) != 1 {
		t.Fatalf("list = %+v", got)
	}
	if k := PinnedTrustKey(); k != pubHex {
		t.Fatalf("pinned key = %s", k)
	}

	// A different server key is refused (not silently re-pinned).
	other := signTestList(t, priv2, []TrustedDevice{{Fingerprint: fp, Name: "evil", Mode: ModeAuto}}, time.Now().Add(time.Hour))
	if err := SaveSignedTrust(other, hex.EncodeToString(pub2)); !errors.Is(err, ErrTrustKeyChanged) {
		t.Fatalf("key change should be refused, got %v", err)
	}

	// A tampered payload does not verify and is not saved.
	bad := list
	bad.Payload = flipLastByte(t, bad.Payload)
	if err := SaveSignedTrust(bad, pubHex); err == nil {
		t.Fatal("tampered list saved")
	}

	// An expired list yields no trust.
	expired := signTestList(t, priv, []TrustedDevice{{Fingerprint: fp, Name: "laptop"}}, time.Now().Add(-time.Minute))
	if err := SaveSignedTrust(expired, pubHex); err == nil {
		t.Fatal("expired list accepted by SaveSignedTrust")
	}
	p, _ := signedTrustPath()
	// Hand-editing the cache: corrupt the signature -> the whole list is untrusted.
	data, _ := os.ReadFile(p)
	var f signedTrustFile
	_ = json.Unmarshal(data, &f)
	f.List.Signature = flipLastByte(t, f.List.Signature)
	out, _ := json.Marshal(f)
	_ = os.WriteFile(p, out, 0o600)
	if _, ok := Lookup(fp); ok {
		t.Fatal("cache with a broken signature still trusted")
	}
	if err := ResetTrust(); err != nil {
		t.Fatal(err)
	}
	if _, ok := Lookup(fp); ok {
		t.Fatal("trusted after reset")
	}
}

// §AJ #10. The pinned key used to be read from the cache file itself, so any
// local process could write a self-signed list and be "trusted" on auto with no
// prompt, no code, no MFA. And a list the server genuinely signed for ANOTHER
// account verified too. Neither may be honoured.
func TestTrustCacheRefusesUnpinnedKeyAndForeignAccount(t *testing.T) {
	// Start from nothing and leave nothing: this test writes the cache file
	// directly, and the package's other tests read the same path.
	_ = ResetTrust()
	t.Cleanup(func() { _ = ResetTrust() })
	const fp = "b676f58a180a7fc204ab3a1c0d24eb9eec33b66faa066569eef3fa0d8096d37c"
	p, _ := signedTrustPath()
	_ = os.MkdirAll(filepath.Dir(p), 0o700)

	// 1. Self-signed by a local attacker: key unknown to this build.
	pub, priv, _ := ed25519.GenerateKey(nil)
	CurrentAccountID = func() string { return "acct" }
	t.Cleanup(func() { CurrentAccountID = nil })
	forged := signTestList(t, priv, []TrustedDevice{{Fingerprint: fp, Name: "evil", Mode: ModeAuto}}, time.Now().Add(time.Hour))
	out, _ := json.Marshal(signedTrustFile{PublicKey: hex.EncodeToString(pub), List: forged, FetchedAt: time.Now()})
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if d, ok := Lookup(fp); ok {
		t.Fatalf("a self-signed cache under an unpinned key was honoured: %+v", d)
	}
	if err := SaveSignedTrust(forged, hex.EncodeToString(pub)); !errors.Is(err, ErrTrustKeyNotPinned) {
		t.Fatalf("SaveSignedTrust under an unpinned key: %v", err)
	}

	// 2. Genuinely signed (key pinned) but for someone else's account.
	t.Setenv(TrustKeysEnv, hex.EncodeToString(pub))
	CurrentAccountID = func() string { return "victim-account" }
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if d, ok := Lookup(fp); ok {
		t.Fatalf("a list for another account was honoured: %+v", d)
	}
	if ok, _ := TrustCacheStatus(); ok {
		t.Fatal("status reports a valid cache for another account")
	}
	// Same list, right account: honoured (the two checks above were the reason).
	CurrentAccountID = func() string { return "acct" }
	if _, ok := Lookup(fp); !ok {
		t.Fatal("a pinned, correctly bound cache was refused")
	}
	// No binding at all: nothing is trusted.
	CurrentAccountID = nil
	if _, ok := Lookup(fp); ok {
		t.Fatal("trusted with no account binding")
	}
}

// §AJ low batch: the identity write discarded its error, so a device that could
// not save its key generated a NEW one every run -- appearing as a different
// device each time and breaking every trust relationship it had.
func TestIdentityIsStableAcrossRuns(t *testing.T) {
	_ = ResetTrust()
	first, err := loadOrCreateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(second) {
		t.Fatal("a second run produced a different identity")
	}
}

// The file is written 0600, and an existing one with looser permissions is
// tightened rather than left alone.
func TestIdentityFilePermissions(t *testing.T) {
	if _, err := loadOrCreateIdentity(); err != nil {
		t.Fatal(err)
	}
	dir, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "lan_identity.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("identity written %o, want 0600", perm)
	}

	// Loosen it the way a bad umask or a restore-from-backup would, then read
	// again: the next load must put it back.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateIdentity(); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(path)
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("a world-readable identity was left at %o", perm)
	}
}

// A key that cannot be saved is reported, not silently replaced next run.
func TestUnsavableIdentityIsAnError(t *testing.T) {
	dir, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "lan_identity.json")
	_ = os.Remove(path)
	// Make the directory unwritable so the temp file cannot be created.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cannot make the config dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, err := loadOrCreateIdentity(); err == nil {
		t.Fatal("an identity that could not be saved was returned as if it had been")
	}
}

// flipLastByte corrupts a base64url value by flipping a bit in the DECODED
// bytes.
//
// These tests used to corrupt by replacing the last two base64 characters with
// "AA", which is not reliably a corruption: the final character of an Ed25519
// signature carries only two significant bits, so that edit left the value
// unchanged around 6% of the time and the assertion silently passed on an
// intact signature. That is what made this test flaky.
func flipLastByte(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		t.Fatalf("not decodable base64url: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	return base64.RawURLEncoding.EncodeToString(raw)
}

// The production and staging signing keys must both be compiled in, or a client
// silently refuses every trust list from that environment -- which shows up as
// "my trusted device keeps asking", not as an error (§AJ #10).
func TestBuiltinTrustKeysCoverBothEnvironments(t *testing.T) {
	const (
		prod    = "fdce17424db15bee0a7f859e93f31f732296870a4209f639e02ec6286c6d327c"
		staging = "87be5b415b53731efbc0fd79e79797c055ea9a9474264acf4965f118028a5e44"
	)
	for name, key := range map[string]string{"production": prod, "staging": staging} {
		if !trustKeyAllowed(key) {
			t.Errorf("the %s signing key is not compiled in", name)
		}
	}
	// A key nobody minted is still refused.
	if trustKeyAllowed(strings.Repeat("ab", 32)) {
		t.Fatal("an unknown key was accepted")
	}
	for _, k := range BuiltinTrustKeys {
		if len(k) != 64 {
			t.Fatalf("built-in key %q is not a 64-character hex ed25519 key", k)
		}
	}
}
