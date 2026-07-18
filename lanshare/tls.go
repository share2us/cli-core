package lanshare

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// certValidity is how long the ephemeral self-signed cert is valid. The cert is
// generated fresh for every receive session, so this only needs to cover a
// single transfer plus clock skew.
const certValidity = 24 * time.Hour

// generateEphemeralCert creates a fresh self-signed P-256 certificate for a
// receive session and returns it alongside the lowercase hex SHA-256 fingerprint
// of its DER certificate (the value embedded in the pairing string / QR and
// pinned by a sender).
func generateEphemeralCert() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "share2us-lan"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("create certificate: %w", err)
	}
	sum := sha256.Sum256(der)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: &tmpl}
	return cert, hex.EncodeToString(sum[:]), nil
}

// certFingerprint returns the lowercase hex SHA-256 fingerprint of a DER cert.
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// serverTLSConfig builds the receiver-side TLS 1.3 config from an ephemeral cert.
func serverTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // 1.3 negotiated; 1.2 floor for old clients
	}
}

// clientTLSConfig builds the sender-side TLS config. It never trusts a CA chain
// (the receiver cert is self-signed); confidentiality comes from TLS and
// authentication comes from either a pinned fingerprint (pinFingerprint != "")
// or, when unpinned, the PAKE / allow-ip layer above.
func clientTLSConfig(pinFingerprint string) *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // self-signed by design; see VerifyPeerCertificate below
		MinVersion:         tls.VersionTLS12,
	}
	if pinFingerprint != "" {
		want := normalizeFingerprint(pinFingerprint)
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("lanshare: peer presented no certificate")
			}
			if got := certFingerprint(rawCerts[0]); got != want {
				return fmt.Errorf("lanshare: peer certificate fingerprint mismatch (possible MITM)")
			}
			return nil
		}
	}
	return cfg
}

// normalizeFingerprint lowercases a hex fingerprint and strips common separators
// (colons/spaces) so pasted values match generated ones.
func normalizeFingerprint(fp string) string {
	out := make([]byte, 0, len(fp))
	for i := 0; i < len(fp); i++ {
		c := fp[i]
		switch {
		case c >= 'A' && c <= 'F':
			out = append(out, c+('a'-'A'))
		case (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9'):
			out = append(out, c)
		}
	}
	return string(out)
}
