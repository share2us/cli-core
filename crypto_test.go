package clicore

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	cases := []string{"", "hello", strings.Repeat("abc123", 40000)}
	for _, input := range cases {
		key, err := NewDataKey()
		if err != nil {
			t.Fatalf("NewDataKey() error = %v", err)
		}
		var encrypted bytes.Buffer
		if err := EncryptStream(&encrypted, strings.NewReader(input), key); err != nil {
			t.Fatalf("EncryptStream() error = %v", err)
		}
		var decrypted bytes.Buffer
		if err := DecryptStream(&decrypted, bytes.NewReader(encrypted.Bytes()), key); err != nil {
			t.Fatalf("DecryptStream() error = %v", err)
		}
		if decrypted.String() != input {
			t.Fatalf("decrypted length = %d, want %d", decrypted.Len(), len(input))
		}
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	key, _ := NewDataKey()
	wrong, _ := NewDataKey()
	var encrypted bytes.Buffer
	if err := EncryptStream(&encrypted, strings.NewReader("secret"), key); err != nil {
		t.Fatalf("EncryptStream() error = %v", err)
	}
	if err := DecryptStream(&bytes.Buffer{}, bytes.NewReader(encrypted.Bytes()), wrong); err == nil {
		t.Fatal("DecryptStream() error = nil, want auth failure")
	}
}

func TestKeyEncodingAndURL(t *testing.T) {
	key, _ := NewDataKey()
	encoded := EncodeKey(key)
	decoded, err := DecodeKey(encoded)
	if err != nil {
		t.Fatalf("DecodeKey() error = %v", err)
	}
	if !bytes.Equal(decoded, key) {
		t.Fatal("decoded key mismatch")
	}
	url := ShareURLWithKey("https://s.share2.us", "pub-1", key)
	fromURL, err := KeyFromShareURL(url)
	if err != nil {
		t.Fatalf("KeyFromShareURL() error = %v", err)
	}
	if !bytes.Equal(fromURL, key) {
		t.Fatal("url key mismatch")
	}
}

func TestDeviceSealedBoxEncryptRoundTrip(t *testing.T) {
	deviceKey, err := NewDeviceKeyPair()
	if err != nil {
		t.Fatalf("NewDeviceKeyPair() error = %v", err)
	}
	contentKey, err := NewDataKey()
	if err != nil {
		t.Fatalf("NewDataKey() error = %v", err)
	}
	sealed, err := SealContentKeyForDevice(contentKey, deviceKey.PublicKey)
	if err != nil {
		t.Fatalf("SealContentKeyForDevice() error = %v", err)
	}
	opened, err := OpenSealedContentKey(sealed, deviceKey.PublicKey, deviceKey.PrivateKey)
	if err != nil {
		t.Fatalf("OpenSealedContentKey() error = %v", err)
	}
	if !bytes.Equal(opened, contentKey) {
		t.Fatal("opened content key mismatch")
	}

	plaintext := strings.Repeat("device to device payload\n", 1024)
	var encrypted bytes.Buffer
	if err := EncryptStream(&encrypted, strings.NewReader(plaintext), contentKey); err != nil {
		t.Fatalf("EncryptStream() error = %v", err)
	}
	reopened, err := OpenSealedContentKey(sealed, deviceKey.PublicKey, deviceKey.PrivateKey)
	if err != nil {
		t.Fatalf("OpenSealedContentKey() second error = %v", err)
	}
	var decrypted bytes.Buffer
	if err := DecryptStream(&decrypted, bytes.NewReader(encrypted.Bytes()), reopened); err != nil {
		t.Fatalf("DecryptStream() error = %v", err)
	}
	if decrypted.String() != plaintext {
		t.Fatal("plaintext round-trip mismatch")
	}
}
