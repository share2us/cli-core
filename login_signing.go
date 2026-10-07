package clicore

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

// PrepareLoginSigningKey persists the signing identity before starting an
// interactive login (ADR-045). Callers must retain this exact pair in the
// completed credential, not replace it after the server has approved the key.
// Existing tokens and encryption keys are preserved even if login is cancelled.
func PrepareLoginSigningKey() (SigningKeyPair, error) {
	cred, err := LoadCredential()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return SigningKeyPair{}, fmt.Errorf("load login signing identity: %w", err)
	}
	pair, err := loginSigningKey(cred)
	if err != nil {
		return SigningKeyPair{}, err
	}
	cred.DeviceSigningPublicKey = pair.PublicKey
	cred.DeviceSigningPrivateKey = pair.PrivateKey
	if err := SaveCredential(cred); err != nil {
		return SigningKeyPair{}, fmt.Errorf("save login signing identity: %w", err)
	}
	return pair, nil
}

func loginSigningKey(cred Credential) (SigningKeyPair, error) {
	if cred.DeviceSigningPrivateKey == "" {
		return NewSigningKeyPair()
	}
	private, err := decodeSigningPrivateKey(cred.DeviceSigningPrivateKey)
	if err != nil {
		return SigningKeyPair{}, fmt.Errorf("invalid local signing private key: %w", err)
	}
	// Derive the public key from the seed, not the cached public half of an
	// Ed25519 private key; this also repairs a missing/stale public-key field.
	private = ed25519.NewKeyFromSeed(private.Seed())
	return SigningKeyPair{
		PublicKey:  base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)),
		PrivateKey: base64.StdEncoding.EncodeToString(private),
	}, nil
}
