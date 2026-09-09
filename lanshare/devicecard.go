// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/url"
	"strings"
)

// A device card is how a device says who it is BEFORE any transfer starts.
//
// Discovery had no stable identity. The listener's TLS certificate is generated
// fresh for every receive session (see generateEphemeralCert), so the only thing
// a scan could learn was a fingerprint that changes whenever the peer restarts —
// and mDNS, the only source of a NAME, is exactly what fails on a Windows Public
// firewall profile, across subnets, and for every tailnet peer. So a
// scan-discovered device showed as a bare address, and anything remembering it
// by fingerprint saw a different device every time it came back.
//
// The card fixes both by carrying, inside that ephemeral certificate:
//
//   - the device's PERSISTENT Ed25519 identity public key (the same one proven
//     during a transfer, and the one the trusted-devices list is keyed on), and
//   - its self-chosen display name,
//
// signed by that identity key over the certificate's OWN public key. That
// binding is what makes it unforgeable: a card lifted from someone else's
// listener is bound to their certificate keypair, so replaying it requires the
// private key of the session it was minted for. An attacker on the LAN cannot
// wear another device's name or identity without that device's identity key.
//
// WHAT IT DOES NOT PROVE. The name is self-chosen — anyone may call their device
// "Hassan's Laptop", and a card proves only that the same device is presenting it
// as last time. Trust stays where ADR-034 put it: server-signed and MFA-gated.
// This makes the LABEL honest, not the device trusted.
//
// TRANSPORT. The card travels as a URI SubjectAltName rather than a custom X.509
// extension, because a private extension needs an OID arc we do not own and
// squatting on somebody else's is worse than a slightly unusual SAN. It is
// standard X.509, needs no registration, survives every TLS stack unchanged, and
// is readable with `openssl x509 -text`. A certificate without one is a device on
// an older build: it simply has no card, and everything degrades to the previous
// behaviour rather than failing.
const (
	cardScheme  = "s2u"
	cardOpaque  = "card"
	cardVersion = "1"
	// cardContext domain-separates this signature from the identity proof made
	// over the TLS exporter material (identitySigContext). The same key signs
	// both, so the two messages must never be confusable.
	cardContext = "s2u-lan-card-v1\x00"
	// maxCardNameLen bounds the name in bytes. A display name is a label, and an
	// unbounded one is a way to bloat every certificate on the network.
	maxCardNameLen = 64
)

// DeviceCard is a verified claim: this identity key, presenting this name.
type DeviceCard struct {
	// Name is the device's self-chosen display name. May be empty.
	Name string
	// Key is the device's persistent Ed25519 identity public key.
	Key ed25519.PublicKey
}

// Fingerprint is the stable device fingerprint — the SAME value the trusted
// devices list is keyed on and VerifyCode renders, so a device found by a scan
// and a device that sends you a file are finally the same device with the same
// code.
func (c DeviceCard) Fingerprint() string { return IdentityFingerprint(c.Key) }

// cardMessage is the exact byte string a card signature covers. The name is
// length-prefixed so no two (name, key) pairs can produce the same message by
// running fields together.
func cardMessage(spkiHash []byte, name string) []byte {
	msg := make([]byte, 0, len(cardContext)+len(spkiHash)+2+len(name))
	msg = append(msg, cardContext...)
	msg = append(msg, spkiHash...)
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(name)))
	msg = append(msg, n[:]...)
	msg = append(msg, name...)
	return msg
}

// spkiHash is SHA-256 over the DER SubjectPublicKeyInfo of a certificate's key.
//
// The card is bound to the KEY rather than to the finished certificate because
// it lives inside that certificate: signing the certificate's own fingerprint
// would change the fingerprint. The public key is fixed before the certificate
// is built, and it is what terminates the TLS session, so binding to it is both
// possible and sufficient.
func spkiHash(pub any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return sum[:], nil
}

// buildCardURI mints the SAN for a listener's certificate. A device with no
// identity key gets no card, which is not an error: it is how the CLI's one-off
// receive sessions and older callers behave.
func buildCardURI(id ed25519.PrivateKey, name string, certPub any) (*url.URL, error) {
	if len(id) != ed25519.PrivateKeySize {
		return nil, nil
	}
	name = strings.TrimSpace(name)
	if len(name) > maxCardNameLen {
		name = strings.ToValidUTF8(name[:maxCardNameLen], "")
	}
	sum, err := spkiHash(certPub)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(id, cardMessage(sum, name))
	pub, ok := id.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("lanshare: identity key is not ed25519")
	}
	q := url.Values{}
	q.Set("v", cardVersion)
	q.Set("k", base64.RawURLEncoding.EncodeToString(pub))
	q.Set("n", base64.RawURLEncoding.EncodeToString([]byte(name)))
	q.Set("s", base64.RawURLEncoding.EncodeToString(sig))
	return &url.URL{Scheme: cardScheme, Opaque: cardOpaque, RawQuery: q.Encode()}, nil
}

// cardFromCert extracts and VERIFIES the card in a peer's certificate.
//
// It returns false for anything it cannot prove: no card, an unknown version, a
// malformed field, a key of the wrong size, or a signature that does not cover
// THIS certificate's public key. There is deliberately no "unverified card"
// result — a caller that could read the name without checking the signature
// would eventually display it, and a name nobody verified is exactly the
// attacker-choosable label this exists to replace.
func cardFromCert(leaf *x509.Certificate) (DeviceCard, bool) {
	if leaf == nil {
		return DeviceCard{}, false
	}
	sum, err := spkiHash(leaf.PublicKey)
	if err != nil {
		return DeviceCard{}, false
	}
	for _, u := range leaf.URIs {
		if u == nil || u.Scheme != cardScheme || u.Opaque != cardOpaque {
			continue
		}
		q := u.Query()
		if q.Get("v") != cardVersion {
			continue // a future version is not ours to guess at
		}
		key, err := base64.RawURLEncoding.DecodeString(q.Get("k"))
		if err != nil || len(key) != ed25519.PublicKeySize {
			continue
		}
		sig, err := base64.RawURLEncoding.DecodeString(q.Get("s"))
		if err != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(q.Get("n"))
		if err != nil || len(raw) > maxCardNameLen {
			continue
		}
		name := sanitizeCardName(string(raw))
		if !ed25519.Verify(key, cardMessage(sum, string(raw)), sig) {
			continue
		}
		return DeviceCard{Name: name, Key: key}, true
	}
	return DeviceCard{}, false
}

// sanitizeCardName strips what a remote-controlled label must never carry into a
// device list: control characters (which can reorder or blank a line in a
// terminal) and the bidirectional overrides that let "photos.exe" render as
// something else entirely. The signature covers the RAW bytes, so this runs
// AFTER verification — cleaning first would let a device fail to verify its own
// card.
func sanitizeCardName(s string) string { return stripControls(s) }

// MaxNameRunes caps any peer-supplied label. A name is a line in a prompt or a
// list; past this it is padding meant to push something off-screen.
const MaxNameRunes = 120

// SanitizeName is the ONE cleaner for every label a remote peer chooses about
// itself or its file before that label reaches a prompt, a device list, a log
// line, or the account's trust list: invalid UTF-8 becomes empty, C0/C1 controls
// (terminal escapes: cursor moves, line clears, OSC titles) and bidirectional
// overrides are dropped, whitespace is trimmed, and the result is capped at
// MaxNameRunes. Security audit §AJ #7: an unauthenticated LAN peer used to
// control the exact text of the transfer-approval prompt, and that text was
// then stored as the trusted-device label for the whole account.
func SanitizeName(s string) string {
	s = stripControls(s)
	n := 0
	for i := range s {
		if n == MaxNameRunes {
			return strings.TrimSpace(s[:i])
		}
		n++
	}
	return s
}

func stripControls(s string) string {
	if !utf8Valid(s) {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x20, r == 0x7f: // C0 controls and DEL
			continue
		case r >= 0x80 && r <= 0x9f: // C1 controls
			continue
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069: // bidi overrides
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "�") == s }
