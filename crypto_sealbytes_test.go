package clicore

import (
	"bytes"
	"testing"
)

func TestSealForDeviceRoundTrip(t *testing.T) {
	kp, err := NewDeviceKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("inject this prompt — with unicode ✓ and length beyond 32 bytes for good measure")
	sealed, err := SealForDevice(msg, kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(sealed), msg) {
		t.Fatal("sealed blob leaks plaintext")
	}
	opened, err := OpenSealedForDevice(sealed, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, msg) {
		t.Fatalf("round-trip mismatch: %q", opened)
	}
	// a different device cannot open it
	other, _ := NewDeviceKeyPair()
	if _, err := OpenSealedForDevice(sealed, other.PublicKey, other.PrivateKey); err == nil {
		t.Fatal("a different device opened the sealed payload")
	}
}
