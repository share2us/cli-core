package clicore

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"
)

// GOLDEN VECTOR — the wire format of a signed hop.
//
// The server verifies hop signatures with its own implementation of the same
// canonical encoding (it cannot import this public library's crypto without
// pulling the whole client into the API). Two implementations of one byte format
// drift silently: a changed field order or length prefix still round-trips inside
// each repo and fails only in production, as "every hop rejected".
//
// So both repos assert THIS vector. It is deterministic — Ed25519 signatures are,
// given the key and message — so any change to SigningBytes on either side fails
// that side's CI. If you change the encoding deliberately, bump
// hopSigningDomain's version AND update the vector in share2us-api in the same
// release.
const (
	goldenSeedHex      = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	goldenPublicKeyB64 = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
	goldenSigningHex   = "0000001573686172653275732f6167656e742d686f702f76310000002431313131313131312d313131312d313131312d313131312d3131313131313131313131310000002432323232323232322d323232322d323232322d323232322d3232323232323232323232320000000b73657373696f6e2d61626300000006636c6175646500000014633256686247566b4c5842796232317764413d3d00000010633256686247566b4c57746c65513d3d0000002434343434343434342d343434342d343434342d343434342d3434343434343434343434340000000a3137393030303030303000000017626d397559325574626d397559325574626d3975593255"
	goldenSignatureB64 = "1Fcz+Gj3MjD7Ly+I0tLDP4MgdLyBHEcSy22VH3mWT3qbWgc7M5JxDUnWBJgb0fvj8PkeZUk/+Xz1lfeAv/b0Bg=="
)

func goldenClaims() HopClaims {
	return HopClaims{
		SenderDeviceID:  "11111111-1111-1111-1111-111111111111",
		TargetDeviceID:  "22222222-2222-2222-2222-222222222222",
		TargetSessionID: "session-abc",
		Tool:            "claude",
		SealedPrompt:    "c2VhbGVkLXByb21wdA==",
		SealedFileKey:   "c2VhbGVkLWtleQ==",
		GoalID:          "44444444-4444-4444-4444-444444444444",
		IssuedAt:        time.Unix(1790000000, 0),
		Nonce:           "bm9uY2Utbm9uY2Utbm9uY2U",
	}
}

func goldenKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(goldenSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestGoldenHopVector(t *testing.T) {
	priv := goldenKey(t)
	c := goldenClaims()

	if got := hex.EncodeToString(c.SigningBytes()); got != goldenSigningHex {
		t.Fatalf("the signing bytes changed — the server will reject every hop.\n got %s\nwant %s", got, goldenSigningHex)
	}
	if got := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)); got != goldenPublicKeyB64 {
		t.Fatalf("public key = %s, want %s", got, goldenPublicKeyB64)
	}
	sig, err := SignHop(c, base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	if sig != goldenSignatureB64 {
		t.Fatalf("signature = %s, want %s", sig, goldenSignatureB64)
	}
	// And the frozen signature verifies with the frozen key — the check the server
	// runs against the same vector.
	if err := VerifyHop(c, goldenSignatureB64, goldenPublicKeyB64); err != nil {
		t.Fatalf("the golden signature does not verify: %v", err)
	}
}
