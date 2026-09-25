package clicore

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func sampleClaims(t *testing.T) HopClaims {
	t.Helper()
	nonce, err := NewHopNonce()
	if err != nil {
		t.Fatal(err)
	}
	return HopClaims{
		SenderDeviceID:  "dev-sender",
		TargetDeviceID:  "dev-target",
		TargetSessionID: "sess-1",
		Tool:            "claude",
		SealedPrompt:    "SEALED-PROMPT-BLOB",
		SealedFileKey:   "SEALED-KEY",
		GoalID:          "goal-1",
		IssuedAt:        time.Unix(1_790_000_000, 0),
		Nonce:           nonce,
	}
}

func TestHopSignatureRoundTrip(t *testing.T) {
	kp, err := NewSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c := sampleClaims(t)
	sig, err := SignHop(c, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyHop(c, sig, kp.PublicKey); err != nil {
		t.Fatalf("a genuine hop did not verify: %v", err)
	}
}

// Every claim is covered. If any one of them could be changed without breaking
// the signature, a hop could be redirected, swapped or moved onto another budget.
func TestEveryClaimIsCovered(t *testing.T) {
	kp, _ := NewSigningKeyPair()
	c := sampleClaims(t)
	sig, _ := SignHop(c, kp.PrivateKey)

	for name, mutate := range map[string]func(*HopClaims){
		"sender":         func(h *HopClaims) { h.SenderDeviceID = "dev-impostor" },
		"target device":  func(h *HopClaims) { h.TargetDeviceID = "dev-other" },
		"target session": func(h *HopClaims) { h.TargetSessionID = "sess-2" },
		"tool":           func(h *HopClaims) { h.Tool = "codex" },
		"prompt":         func(h *HopClaims) { h.SealedPrompt = "SWAPPED" },
		"file key":       func(h *HopClaims) { h.SealedFileKey = "OTHER-KEY" },
		"goal":           func(h *HopClaims) { h.GoalID = "goal-2" },
		"issued at":      func(h *HopClaims) { h.IssuedAt = h.IssuedAt.Add(time.Second) },
		"nonce":          func(h *HopClaims) { h.Nonce = "reused" },
	} {
		altered := c
		mutate(&altered)
		if err := VerifyHop(altered, sig, kp.PublicKey); !errors.Is(err, ErrHopSignature) {
			t.Fatalf("changing the %s did not break the signature (err = %v)", name, err)
		}
	}
}

func TestAnotherKeyCannotVouch(t *testing.T) {
	real, _ := NewSigningKeyPair()
	impostor, _ := NewSigningKeyPair()
	c := sampleClaims(t)
	sig, _ := SignHop(c, impostor.PrivateKey)
	if err := VerifyHop(c, sig, real.PublicKey); !errors.Is(err, ErrHopSignature) {
		t.Fatalf("a hop signed by another key verified: %v", err)
	}
}

// With a delimiter instead of length prefixes, ("ab","c") and ("a","bc") would
// serialize the same and one signature would cover both.
func TestSigningBytesAreUnambiguous(t *testing.T) {
	a := HopClaims{SenderDeviceID: "ab", TargetDeviceID: "c", IssuedAt: time.Unix(0, 0)}
	b := HopClaims{SenderDeviceID: "a", TargetDeviceID: "bc", IssuedAt: time.Unix(0, 0)}
	if bytes.Equal(a.SigningBytes(), b.SigningBytes()) {
		t.Fatal("two different claim sets produce the same signing bytes")
	}
}

// The signature is tied to its purpose: the same key signing the same fields for
// something else must not produce a valid hop signature.
func TestSigningBytesAreDomainSeparated(t *testing.T) {
	c := sampleClaims(t)
	if !bytes.Contains(c.SigningBytes(), []byte(hopSigningDomain)) {
		t.Fatal("the signing bytes carry no domain tag")
	}
}

// Sub-second differences in how a timestamp is carried must not change what is
// signed: both sides reduce it to whole seconds.
func TestSigningBytesIgnoreSubSecondPrecision(t *testing.T) {
	c := sampleClaims(t)
	d := c
	d.IssuedAt = c.IssuedAt.Add(400 * time.Millisecond)
	if !bytes.Equal(c.SigningBytes(), d.SigningBytes()) {
		t.Fatal("a sub-second difference changed the signed bytes")
	}
}

func TestMalformedInputsFailClosedWithoutPanicking(t *testing.T) {
	kp, _ := NewSigningKeyPair()
	c := sampleClaims(t)
	sig, _ := SignHop(c, kp.PrivateKey)

	for name, tc := range map[string]struct{ sig, key string }{
		"empty signature":    {"", kp.PublicKey},
		"garbage signature":  {"!!!not base64!!!", kp.PublicKey},
		"short signature":    {"AAAA", kp.PublicKey},
		"empty key":          {sig, ""},
		"garbage key":        {sig, "not-a-key"},
		"x25519-length key":  {sig, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		"private key as pub": {sig, kp.PrivateKey},
	} {
		if err := VerifyHop(c, tc.sig, tc.key); !errors.Is(err, ErrHopSignature) {
			t.Fatalf("%s: err = %v, want ErrHopSignature", name, err)
		}
	}
	if _, err := SignHop(c, "not-a-key"); err == nil {
		t.Fatal("signing with a garbage key succeeded")
	}
}

func TestFreshnessWindow(t *testing.T) {
	kp, _ := NewSigningKeyPair()
	c := sampleClaims(t)
	sig, _ := SignHop(c, kp.PrivateKey)
	window := 5 * time.Minute

	if err := VerifyHopFresh(c, sig, kp.PublicKey, c.IssuedAt.Add(time.Minute), window); err != nil {
		t.Fatalf("a hop one minute old was refused: %v", err)
	}
	// A replay.
	if err := VerifyHopFresh(c, sig, kp.PublicKey, c.IssuedAt.Add(time.Hour), window); !errors.Is(err, ErrHopStale) {
		t.Fatalf("an hour-old hop = %v, want ErrHopStale", err)
	}
	// Minted in the future, which would otherwise stay "fresh" indefinitely.
	if err := VerifyHopFresh(c, sig, kp.PublicKey, c.IssuedAt.Add(-time.Hour), window); !errors.Is(err, ErrHopStale) {
		t.Fatalf("a hop from the future = %v, want ErrHopStale", err)
	}
}

// A forged hop must be reported as a bad signature, not as stale. Checking the
// signature first means an attacker cannot probe the freshness window with
// unsigned hops and chosen timestamps.
func TestSignatureIsCheckedBeforeFreshness(t *testing.T) {
	real, _ := NewSigningKeyPair()
	impostor, _ := NewSigningKeyPair()
	c := sampleClaims(t)
	forged, _ := SignHop(c, impostor.PrivateKey)
	if err := VerifyHopFresh(c, forged, real.PublicKey, c.IssuedAt.Add(time.Hour), 5*time.Minute); !errors.Is(err, ErrHopSignature) {
		t.Fatalf("a stale forgery = %v, want ErrHopSignature", err)
	}
}

func TestNoncesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		n, err := NewHopNonce()
		if err != nil {
			t.Fatal(err)
		}
		if seen[n] {
			t.Fatalf("nonce repeated after %d draws", i)
		}
		seen[n] = true
	}
}
