package lanshare

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
)

// identitySigContext domain-separates the identity signature from any other use
// of the TLS exporter keying material (e.g. the PAKE key-confirmation MAC).
const identitySigContext = "s2u-lan-identity-v1\x00"

// IdentityFingerprint is the stable lowercase hex SHA-256 of an Ed25519 identity
// public key — the value a receiver stores/pins in its trusted-devices list and
// (via VerifyCode) shows as a 6-digit code.
func IdentityFingerprint(pub ed25519.PublicKey) string {
	if len(pub) == 0 {
		return ""
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// identityMessage is the exact byte string an identity signature covers: a
// domain separator followed by the TLS channel-binding EKM, so the proof is
// bound to THIS session — it cannot be replayed on another connection, and a
// man-in-the-middle running two distinct TLS sessions cannot relay it.
func identityMessage(ekm []byte) []byte {
	msg := make([]byte, 0, len(identitySigContext)+len(ekm))
	msg = append(msg, identitySigContext...)
	msg = append(msg, ekm...)
	return msg
}
