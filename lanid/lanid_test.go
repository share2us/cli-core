package lanid

import (
	"os"
	"testing"

	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func TestSignedTrustCacheIsTheOnlySourceOfTrust(t *testing.T) {
	t.Cleanup(func() { _ = ResetTrust() })
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubHex := hex.EncodeToString(pub)
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
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	other := signTestList(t, priv2, []TrustedDevice{{Fingerprint: fp, Name: "evil", Mode: ModeAuto}}, time.Now().Add(time.Hour))
	if err := SaveSignedTrust(other, hex.EncodeToString(pub2)); !errors.Is(err, ErrTrustKeyChanged) {
		t.Fatalf("key change should be refused, got %v", err)
	}

	// A tampered payload does not verify and is not saved.
	bad := list
	bad.Payload = bad.Payload[:len(bad.Payload)-2] + "AA"
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
	f.List.Signature = f.List.Signature[:len(f.List.Signature)-2] + "AA"
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
