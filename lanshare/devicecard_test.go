// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testIdentity(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// certWithCard mints a listener certificate the way a receive session does and
// hands back its parsed leaf, which is exactly what a prober sees.
func certWithCard(t *testing.T, id ed25519.PrivateKey, name string) *x509.Certificate {
	t.Helper()
	cert, _, err := generateEphemeralCert(id, name)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return mustLeaf(t, cert.Certificate[0])
}

func mustLeaf(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return leaf
}

// mintCertWithURIs builds a certificate around a FRESH keypair carrying whatever
// SANs it is given. It is how an attacker is modelled: their own TLS key, and a
// card copied from somebody else.
func mintCertWithURIs(t *testing.T, uris []*url.URL) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return mintAround(t, key, uris)
}

// mintCertWithTamperedName keeps the certificate KEY intact and edits only the
// name in the card, so a failure isolates the signature over the name rather
// than also tripping the key binding.
func mintCertWithTamperedName(t *testing.T, id ed25519.PrivateKey, real, fake string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := buildCardURI(id, real, &key.PublicKey)
	if err != nil || u == nil {
		t.Fatalf("build card: %v", err)
	}
	q := u.Query()
	q.Set("n", base64.RawURLEncoding.EncodeToString([]byte(fake)))
	u.RawQuery = q.Encode()
	return mintAround(t, key, []*url.URL{u})
}

func mintAround(t *testing.T, key *ecdsa.PrivateKey, uris []*url.URL) *x509.Certificate {
	t.Helper()
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "share2us-lan"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return mustLeaf(t, der)
}

func TestCardCarriesNameAndStableIdentity(t *testing.T) {
	id := testIdentity(t)
	card, ok := cardFromCert(certWithCard(t, id, "kestrel"))
	if !ok {
		t.Fatal("a certificate minted with an identity must carry a verifiable card")
	}
	if card.Name != "kestrel" {
		t.Errorf("name = %q, want kestrel", card.Name)
	}
	want := IdentityFingerprint(id.Public().(ed25519.PublicKey))
	if card.Fingerprint() != want {
		t.Errorf("fingerprint = %q, want %q", card.Fingerprint(), want)
	}
}

// The whole point of the identity key: it does not change when the session does.
// The certificate fingerprint DOES, which is why discovery could not remember a
// device before.
func TestIdentitySurvivesANewSessionButTheCertificateDoesNot(t *testing.T) {
	id := testIdentity(t)
	a, fpA, err := generateEphemeralCert(id, "kestrel")
	if err != nil {
		t.Fatal(err)
	}
	b, fpB, err := generateEphemeralCert(id, "kestrel")
	if err != nil {
		t.Fatal(err)
	}
	if fpA == fpB {
		t.Fatal("certificates are supposed to be ephemeral; two sessions matched")
	}
	cardA, okA := cardFromCert(mustLeaf(t, a.Certificate[0]))
	cardB, okB := cardFromCert(mustLeaf(t, b.Certificate[0]))
	if !okA || !okB {
		t.Fatal("both sessions must publish a card")
	}
	if cardA.Fingerprint() != cardB.Fingerprint() {
		t.Error("the device identity changed between sessions; nothing could remember this device")
	}
}

// The binding that makes a card unforgeable. Lifting a valid card onto another
// device's certificate must fail, or an attacker on the LAN could wear any name
// and any identity simply by copying what a peer advertises.
func TestACardLiftedOntoAnotherCertificateIsRefused(t *testing.T) {
	victim := certWithCard(t, testIdentity(t), "kestrel")
	attacker := certWithCard(t, testIdentity(t), "attacker")

	_ = attacker // the attacker's own certificate verifies; the point is what happens to a COPIED card
	stolen := mintCertWithURIs(t, victim.URIs)
	if _, ok := cardFromCert(stolen); ok {
		t.Fatal("IMPERSONATION: a card replayed on a different certificate verified")
	}
}

func TestNoIdentityMeansNoCardRatherThanAnError(t *testing.T) {
	cert, _, err := generateEphemeralCert(nil, "kestrel")
	if err != nil {
		t.Fatalf("a device without an identity must still get a certificate: %v", err)
	}
	if _, ok := cardFromCert(mustLeaf(t, cert.Certificate[0])); ok {
		t.Error("a card appeared without an identity key to sign it")
	}
}

func TestATamperedNameNoLongerVerifies(t *testing.T) {
	tampered := mintCertWithTamperedName(t, testIdentity(t), "kestrel", "Hassan's Laptop")
	if _, ok := cardFromCert(tampered); ok {
		t.Fatal("IMPERSONATION: the name was edited and the card still verified")
	}
}

func TestNameIsBoundedAndStrippedOfControlCharacters(t *testing.T) {
	id := testIdentity(t)
	long := strings.Repeat("n", maxCardNameLen*3)
	card, ok := cardFromCert(certWithCard(t, id, long))
	if !ok {
		t.Fatal("an over-long name should be truncated, not rejected outright")
	}
	if len(card.Name) > maxCardNameLen {
		t.Errorf("name is %d bytes; every certificate on the network carries this", len(card.Name))
	}

	// A device list is drawn in a UI and, for the CLI, a terminal. A name that
	// can carry \r or a bidi override can blank a line or make a name read as
	// another device entirely.
	card, ok = cardFromCert(certWithCard(t, id, "kes\rtrel‮"))
	if !ok {
		t.Fatal("a name with control characters should be cleaned, not dropped")
	}
	if strings.ContainsAny(card.Name, "\r\n") || strings.ContainsRune(card.Name, 0x202e) {
		t.Errorf("name %q still carries control characters", card.Name)
	}
}

// The signature covers the RAW name, so cleaning has to happen after verifying —
// otherwise a device with a stripped character in its name could not present a
// card that verified against itself.
func TestSanitizingDoesNotBreakVerification(t *testing.T) {
	if _, ok := cardFromCert(certWithCard(t, testIdentity(t), "kes\rtrel")); !ok {
		t.Fatal("a device could not verify its own card")
	}
}
