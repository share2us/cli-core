// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"bytes"
	"testing"
)

func TestFormResponseRoundTrip(t *testing.T) {
	owner, err := NewDeviceKeyPair()
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}
	submitter, err := NewDeviceKeyPair()
	if err != nil {
		t.Fatalf("submitter key: %v", err)
	}
	answers := []byte(`{"form_version":1,"answers":{"name":"Ada","role":["Engineer"]}}`)

	body, sealed, err := SealFormResponse(answers, []string{owner.PublicKey, submitter.PublicKey})
	if err != nil {
		t.Fatalf("SealFormResponse: %v", err)
	}
	if len(sealed) != 2 {
		t.Fatalf("sealed keys = %d, want 2", len(sealed))
	}

	// Owner opens with their sealed key.
	got, err := OpenFormResponse(body, sealed[0], owner.PublicKey, owner.PrivateKey)
	if err != nil {
		t.Fatalf("owner OpenFormResponse: %v", err)
	}
	if !bytes.Equal(got, answers) {
		t.Fatalf("owner decrypt mismatch: %s", got)
	}

	// Submitter opens their own copy (receipt).
	got, err = OpenFormResponse(body, sealed[1], submitter.PublicKey, submitter.PrivateKey)
	if err != nil {
		t.Fatalf("submitter OpenFormResponse: %v", err)
	}
	if !bytes.Equal(got, answers) {
		t.Fatalf("submitter decrypt mismatch: %s", got)
	}

	// A third party with the body + a sealed key but the wrong keypair cannot open it.
	stranger, _ := NewDeviceKeyPair()
	if _, err := OpenFormResponse(body, sealed[0], stranger.PublicKey, stranger.PrivateKey); err == nil {
		t.Fatalf("stranger decrypted a response sealed to the owner")
	}
}

func TestSealOpenBytesWithKey(t *testing.T) {
	key, _ := NewDataKey()
	msg := []byte("hello forms")
	enc, err := SealBytesWithKey(key, msg)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	dec, err := OpenBytesWithKey(key, enc)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(dec, msg) {
		t.Fatalf("round trip mismatch: %s", dec)
	}
	wrong, _ := NewDataKey()
	if _, err := OpenBytesWithKey(wrong, enc); err == nil {
		t.Fatalf("opened with wrong key")
	}
}
