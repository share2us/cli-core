// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// A tail-truncated ciphertext must be rejected, not silently accepted as a
// short file. This is the core of the H2 fix: the end-of-stream is now
// authenticated, so a malicious server/relay cannot drop chunks and re-terminate.
func TestDecryptStreamDetectsTruncation(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatalf("NewDataKey() error = %v", err)
	}
	input := bytes.Repeat([]byte("share2us-truncation-probe\n"), 8000) // > 3 chunks

	var enc bytes.Buffer
	if err := EncryptStream(&enc, bytes.NewReader(input), key); err != nil {
		t.Fatalf("EncryptStream() error = %v", err)
	}
	full := enc.Bytes()

	// The complete stream decrypts cleanly and exactly.
	var ok bytes.Buffer
	if err := DecryptStream(&ok, bytes.NewReader(full), key); err != nil {
		t.Fatalf("DecryptStream(full) error = %v", err)
	}
	if !bytes.Equal(ok.Bytes(), input) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", ok.Len(), len(input))
	}

	// Every strict prefix (a truncated tail) must be rejected.
	for _, cut := range []int{hkdfHeaderSize, hkdfHeaderSize + 10, len(full) / 2, len(full) - chunkSize, len(full) - 100, len(full) - 1} {
		if cut < hkdfHeaderSize || cut >= len(full) {
			continue
		}
		var out bytes.Buffer
		if err := DecryptStream(&out, bytes.NewReader(full[:cut]), key); err == nil {
			t.Errorf("DecryptStream accepted a truncated stream (cut %d/%d)", cut, len(full))
		}
	}
}

// Flipping any ciphertext byte must fail the AEAD tag (integrity).
func TestDecryptStreamRejectsTamper(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatalf("NewDataKey() error = %v", err)
	}
	var enc bytes.Buffer
	if err := EncryptStream(&enc, bytes.NewReader([]byte("top secret payload")), key); err != nil {
		t.Fatalf("EncryptStream() error = %v", err)
	}
	blob := enc.Bytes()
	blob[len(blob)-1] ^= 0x01 // flip a bit in the final chunk's tag/ciphertext

	var out bytes.Buffer
	if err := DecryptStream(&out, bytes.NewReader(blob), key); err == nil {
		t.Error("DecryptStream accepted a tampered ciphertext")
	}
}

// Ciphertexts written in the pre-1.2 (1,1) framing must still decrypt, so shares
// encrypted before the authenticated terminator existed keep opening.
func TestDecryptStreamLegacyV1(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatalf("NewDataKey() error = %v", err)
	}
	cases := [][]byte{
		{},
		[]byte("hello legacy"),
		bytes.Repeat([]byte("x"), chunkSize*2+123), // multi-chunk
	}
	for _, input := range cases {
		blob := legacyEncryptV1(t, key, input)
		var out bytes.Buffer
		if err := DecryptStream(&out, bytes.NewReader(blob), key); err != nil {
			t.Fatalf("DecryptStream(legacy, %d bytes) error = %v", len(input), err)
		}
		if !bytes.Equal(out.Bytes(), input) {
			t.Fatalf("legacy decrypt mismatch: got %d bytes, want %d", out.Len(), len(input))
		}
	}
}

// legacyEncryptV1 reproduces the old (1,1) wire format: [magic][1,1][nonceBase]
// then [uint32 len][ciphertext(AAD=nil)] chunks ended by an unauthenticated
// zero-length marker. Same package, so it can reach the unexported helpers.
func legacyEncryptV1(t *testing.T, key, input []byte) []byte {
	t.Helper()
	aead, err := newAEAD(key)
	if err != nil {
		t.Fatalf("newAEAD() error = %v", err)
	}
	nonceBase := make([]byte, aead.NonceSize())
	for i := range nonceBase {
		nonceBase[i] = byte(i + 1)
	}
	var buf bytes.Buffer
	buf.Write(encryptionMagic[:])
	buf.WriteByte(encVersionMajor)
	buf.WriteByte(encVersionLegacy)
	buf.Write(nonceBase)

	counter := uint64(0)
	for off := 0; off < len(input); off += chunkSize {
		end := off + chunkSize
		if end > len(input) {
			end = len(input)
		}
		ct := aead.Seal(nil, nonceFor(nonceBase, counter), input[off:end], nil)
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(ct)))
		buf.Write(ct)
		counter++
	}
	_ = binary.Write(&buf, binary.BigEndian, uint32(0)) // legacy terminator
	return buf.Bytes()
}

// Ciphertexts written in the (1,2) framing must still decrypt. That format was
// written by every client up to 2026-09-10, so the shares in existence today are
// overwhelmingly this one.
func TestDecryptStreamAEADV2(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatalf("NewDataKey() error = %v", err)
	}
	cases := [][]byte{
		{},
		[]byte("hello v1.2"),
		bytes.Repeat([]byte("y"), chunkSize*2+7), // multi-chunk
	}
	for _, input := range cases {
		blob := encryptV2(t, key, input, nil)
		var out bytes.Buffer
		if err := DecryptStream(&out, bytes.NewReader(blob), key); err != nil {
			t.Fatalf("DecryptStream(v1.2, %d bytes) error = %v", len(input), err)
		}
		if !bytes.Equal(out.Bytes(), input) {
			t.Fatalf("v1.2 decrypt mismatch: got %d bytes, want %d", out.Len(), len(input))
		}
	}
	// And a truncated (1,2) tail is still caught, as it was before.
	blob := encryptV2(t, key, bytes.Repeat([]byte("z"), chunkSize*3), nil)
	var out bytes.Buffer
	if err := DecryptStream(&out, bytes.NewReader(blob[:len(blob)-40]), key); err == nil {
		t.Error("DecryptStream accepted a truncated v1.2 stream")
	}
}

// THE REASON (1,3) EXISTS. In (1,2) the nonce was 4 random bytes plus the chunk
// counter, so two streams under one data key that happened to draw the same 4
// bytes produced the SAME keystream: 32 bits of luck stood between a reused data
// key and a total loss of confidentiality. This test forces that collision to
// show it is real, and to show it is not recoverable by any other part of the
// format -- the additional data differs and the ciphertexts still match.
func TestV2NonceCollisionRepeatsTheKeystream(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatalf("NewDataKey() error = %v", err)
	}
	plaintext := []byte("the same message, encrypted twice under one data key")

	// Two nonce bases that AGREE in the first 4 bytes (the only random part the
	// nonce ever used) and differ afterwards (so the headers, and thus the AAD,
	// are not identical).
	baseA := []byte{9, 9, 9, 9, 1, 1, 1, 1, 1, 1, 1, 1}
	baseB := []byte{9, 9, 9, 9, 2, 2, 2, 2, 2, 2, 2, 2}

	a := encryptV2(t, key, plaintext, baseA)
	b := encryptV2(t, key, plaintext, baseB)

	// Strip header + length + final flag; compare the ciphertext bodies without
	// their tags, which is exactly the keystream-XORed plaintext.
	bodyA := a[headerSize+5 : len(a)-16]
	bodyB := b[headerSize+5 : len(b)-16]
	if !bytes.Equal(bodyA, bodyB) {
		t.Fatal("expected the old format to repeat its keystream on a 4-byte collision")
	}

	// (1,3) has no such knob. The only per-stream input is a 16-byte salt that
	// feeds the KEY, and the caller cannot reach it at all.
	var c1, c2 bytes.Buffer
	if err := EncryptStream(&c1, bytes.NewReader(plaintext), key); err != nil {
		t.Fatalf("EncryptStream() error = %v", err)
	}
	if err := EncryptStream(&c2, bytes.NewReader(plaintext), key); err != nil {
		t.Fatalf("EncryptStream() error = %v", err)
	}
	if bytes.Equal(c1.Bytes(), c2.Bytes()) {
		t.Fatal("two (1,3) streams under one key produced identical ciphertext")
	}
}

// One data key, many streams: every one must round-trip, and no two may come out
// the same despite identical plaintext.
func TestOneDataKeyEncryptsManyStreams(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatalf("NewDataKey() error = %v", err)
	}
	plaintext := bytes.Repeat([]byte("reused data key\n"), 5000) // multi-chunk
	seen := make(map[string]bool)
	for i := 0; i < 32; i++ {
		var enc bytes.Buffer
		if err := EncryptStream(&enc, bytes.NewReader(plaintext), key); err != nil {
			t.Fatalf("EncryptStream(%d) error = %v", i, err)
		}
		if seen[string(enc.Bytes())] {
			t.Fatalf("stream %d repeated an earlier ciphertext", i)
		}
		seen[string(enc.Bytes())] = true

		var out bytes.Buffer
		if err := DecryptStream(&out, bytes.NewReader(enc.Bytes()), key); err != nil {
			t.Fatalf("DecryptStream(%d) error = %v", i, err)
		}
		if !bytes.Equal(out.Bytes(), plaintext) {
			t.Fatalf("round-trip %d mismatch", i)
		}
	}
}

// The per-stream material must be in the KEY, not in the nonce.
func TestStreamKeyDerivation(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatalf("NewDataKey() error = %v", err)
	}
	saltA := bytes.Repeat([]byte{0xA0}, saltSize)
	saltB := append(bytes.Repeat([]byte{0xA0}, saltSize-1), 0xA1) // one bit of difference
	k1, err := deriveStreamKey(key, saltA)
	if err != nil {
		t.Fatalf("deriveStreamKey() error = %v", err)
	}
	k2, err := deriveStreamKey(key, saltB)
	if err != nil {
		t.Fatalf("deriveStreamKey() error = %v", err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("different salts derived the same stream key")
	}
	if bytes.Equal(k1, key) {
		t.Fatal("the stream key is the data key")
	}
	if len(k1) != 32 {
		t.Fatalf("stream key is %d bytes, want 32", len(k1))
	}
	// deriveStreamKey is deterministic, or an existing ciphertext would stop opening.
	again, err := deriveStreamKey(key, saltA)
	if err != nil || !bytes.Equal(k1, again) {
		t.Fatal("deriveStreamKey is not deterministic")
	}
	// The nonce carries the counter and nothing else.
	if n := streamNonce(0); !bytes.Equal(n, make([]byte, nonceBaseSize)) {
		t.Fatalf("streamNonce(0) = %x, want all zeroes", n)
	}
	if n0, n1 := streamNonce(0), streamNonce(1); bytes.Equal(n0, n1) {
		t.Fatal("streamNonce repeated across counters")
	}
}

// The header a fresh stream writes: magic, 1, 3, then a salt that changes every
// time.
func TestEncryptStreamWritesDerivedHeader(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatalf("NewDataKey() error = %v", err)
	}
	var a, b bytes.Buffer
	if err := EncryptStream(&a, bytes.NewReader([]byte("x")), key); err != nil {
		t.Fatalf("EncryptStream() error = %v", err)
	}
	if err := EncryptStream(&b, bytes.NewReader([]byte("x")), key); err != nil {
		t.Fatalf("EncryptStream() error = %v", err)
	}
	head := a.Bytes()[:hkdfHeaderSize]
	if string(head[:4]) != string(encryptionMagic[:]) {
		t.Fatalf("magic = %q", head[:4])
	}
	if head[4] != encVersionMajor || head[5] != encVersionHKDF {
		t.Fatalf("version = %d.%d, want %d.%d", head[4], head[5], encVersionMajor, encVersionHKDF)
	}
	if bytes.Equal(head[headerPrefixSize:], b.Bytes()[headerPrefixSize:hkdfHeaderSize]) {
		t.Fatal("two streams drew the same salt")
	}
}

// encryptV2 reproduces the retired (1,2) wire format: [magic][1,2][nonceBase]
// then [uint32 len][finalByte][ciphertext(AAD=header+finalByte)] chunks, the last
// one flagged. Pass a nonceBase to pin it; nil draws a random one.
func encryptV2(t *testing.T, key, input, nonceBase []byte) []byte {
	t.Helper()
	aead, err := newAEAD(key)
	if err != nil {
		t.Fatalf("newAEAD() error = %v", err)
	}
	if nonceBase == nil {
		nonceBase = make([]byte, nonceBaseSize)
		for i := range nonceBase {
			nonceBase[i] = byte(i * 7)
		}
	}
	header := make([]byte, 0, headerSize)
	header = append(header, encryptionMagic[:]...)
	header = append(header, encVersionMajor, encVersionAEAD)
	header = append(header, nonceBase...)

	var buf bytes.Buffer
	buf.Write(header)
	counter := uint64(0)
	for off := 0; ; off += chunkSize {
		end := off + chunkSize
		if end > len(input) {
			end = len(input)
		}
		final := end >= len(input)
		finalByte := byte(0)
		if final {
			finalByte = 1
		}
		ct := aead.Seal(nil, nonceFor(nonceBase, counter), input[off:end], chunkAAD(header, finalByte))
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(ct)))
		buf.WriteByte(finalByte)
		buf.Write(ct)
		counter++
		if final {
			return buf.Bytes()
		}
	}
}
