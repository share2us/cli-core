// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

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

func TestFileContentKeyRoundTrip(t *testing.T) {
	kp, _ := NewDeviceKeyPair()
	ck, err := NewContentKey()
	if err != nil || len(ck) != 32 {
		t.Fatalf("content key: %v len=%d", err, len(ck))
	}
	// encrypt a "file" with the content key
	plain := bytes.Repeat([]byte("screenshot-bytes-"), 500)
	var enc bytes.Buffer
	if err := EncryptStream(&enc, bytes.NewReader(plain), ck); err != nil {
		t.Fatal(err)
	}
	// seal the content key to the device, then open + decrypt
	sealed, err := SealContentKeyForDevice(ck, kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenSealedContentKey(sealed, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	if err := DecryptStream(&dec, bytes.NewReader(enc.Bytes()), opened); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Bytes(), plain) {
		t.Fatal("file round-trip mismatch")
	}
	if bytes.Contains(enc.Bytes(), []byte("screenshot-bytes")) {
		t.Fatal("ciphertext leaks plaintext")
	}
}
