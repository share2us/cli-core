// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/pbkdf2"
)

// Portal web-key setup from the CLI (ADR-046 Phase 2). The CLI can create the account's
// web key so the owner does not have to in the portal. The wrapping format MUST match the
// portal's lib/forms-crypto.ts so the portal can unwrap it with the passphrase:
//
//	content      = the X25519 box private key (32 bytes)
//	wrapKey      = PBKDF2-HMAC-SHA256(passphrase, salt, 600000, 32)
//	wrapped      = base64std( iv(12) || AES-256-GCM(content, wrapKey, iv) )
//	kdf          = {"v":1,"algo":"PBKDF2-SHA256","hash":"SHA-256","iterations":600000,"salt":base64std}
//
// The passphrase never leaves the client; only the wrapped blob + kdf are uploaded.
const (
	webKeyPBKDF2Iterations = 600000
	webKeyPBKDF2SaltBytes  = 16
)

// GenerateWebKey creates a new web key wrapped with the given passphrase, in the exact
// format the portal unwraps.
func GenerateWebKey(passphrase string) (AccountWebKey, error) {
	kp, err := NewDeviceKeyPair()
	if err != nil {
		return AccountWebKey{}, err
	}
	priv, err := decodeDeviceKey(kp.PrivateKey)
	if err != nil {
		return AccountWebKey{}, err
	}
	salt := make([]byte, webKeyPBKDF2SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return AccountWebKey{}, err
	}
	wrapKey := pbkdf2.Key([]byte(passphrase), salt, webKeyPBKDF2Iterations, 32, sha256.New)
	aead, err := newAEAD(wrapKey)
	if err != nil {
		return AccountWebKey{}, err
	}
	iv := make([]byte, aead.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return AccountWebKey{}, err
	}
	wrapped := aead.Seal(iv, iv, priv, nil) // iv || ciphertext||tag
	kdf, err := json.Marshal(map[string]any{
		"v":          1,
		"algo":       "PBKDF2-SHA256",
		"hash":       "SHA-256",
		"iterations": webKeyPBKDF2Iterations,
		"salt":       base64.StdEncoding.EncodeToString(salt),
	})
	if err != nil {
		return AccountWebKey{}, err
	}
	return AccountWebKey{
		PublicKey:         kp.PublicKey,
		WrappedPrivateKey: base64.StdEncoding.EncodeToString(wrapped),
		KDF:               kdf,
	}, nil
}

// NewWebKeyPassphrase returns a strong random passphrase for a web key, for when the user
// does not supply one. ~132 bits of entropy, URL-safe so it is easy to copy.
func NewWebKeyPassphrase() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// SaveWebKey registers or rotates the account's web key (PUT /v1/account/web-key).
func (c *Client) SaveWebKey(ctx context.Context, key AccountWebKey) error {
	return c.doJSON(ctx, http.MethodPut, "/v1/account/web-key", key, nil)
}
