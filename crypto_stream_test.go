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
	for _, cut := range []int{headerSize, headerSize + 10, len(full) / 2, len(full) - chunkSize, len(full) - 100, len(full) - 1} {
		if cut < headerSize || cut >= len(full) {
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
