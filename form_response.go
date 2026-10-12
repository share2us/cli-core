// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// Interactive form-response crypto (ADR-046). A response body is AES-256-GCM encrypted
// under a random per-response content key; that key is then sealed (NaCl anonymous box,
// via SealContentKeyForDevice) once per reader device public key — the owner's devices,
// plus the submitter's own device for a receipt. The submitter's browser does the sealing
// with libsodium.js (crypto_box_seal) + WebCrypto AES-GCM, which interoperate byte-for-byte
// with the helpers here, so the CLI/GUI can open what the portal produced and vice versa.

// SealBytesWithKey encrypts plaintext with AES-256-GCM under a 32-byte key and returns
// base64(nonce||ciphertext||tag). The 12-byte GCM nonce matches a WebCrypto AES-GCM IV.
func SealBytesWithKey(key, plaintext []byte) (string, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// OpenBytesWithKey reverses SealBytesWithKey, accepting std or url base64.
func OpenBytesWithKey(key []byte, encoded string) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	raw, err := decodeFlexibleBase64(encoded)
	if err != nil {
		return nil, err
	}
	if len(raw) < aead.NonceSize() {
		return nil, errors.New("open form response: ciphertext too short")
	}
	nonce, ct := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	return aead.Open(nil, nonce, ct, nil)
}

// SealFormResponse encrypts a response body and seals the content key to each reader
// device public key. It returns the base64 body and a parallel slice of base64 sealed
// keys (one per readerPublicKeys entry, in order). Used by Go callers and tests; the
// portal performs the equivalent in the browser.
func SealFormResponse(answers []byte, readerPublicKeys []string) (body string, sealedKeys []string, err error) {
	if len(readerPublicKeys) == 0 {
		return "", nil, errors.New("seal form response: no reader keys")
	}
	key, err := NewDataKey()
	if err != nil {
		return "", nil, err
	}
	body, err = SealBytesWithKey(key, answers)
	if err != nil {
		return "", nil, err
	}
	sealedKeys = make([]string, 0, len(readerPublicKeys))
	for _, pub := range readerPublicKeys {
		sealed, err := SealContentKeyForDevice(key, pub)
		if err != nil {
			return "", nil, err
		}
		sealedKeys = append(sealedKeys, sealed)
	}
	return body, sealedKeys, nil
}

// OpenFormResponse opens an E2E form-response body: unseal the per-response content key
// with this device's keypair, then AES-256-GCM-open the body.
func OpenFormResponse(bodyB64, sealedKeyB64, devicePublicKey, devicePrivateKey string) ([]byte, error) {
	key, err := OpenSealedContentKey(sealedKeyB64, devicePublicKey, devicePrivateKey)
	if err != nil {
		return nil, err
	}
	return OpenBytesWithKey(key, bodyB64)
}
