package clicore

// Secure ShareNet primitives (ADR-051 option A; docs/design/secure-sharenet-build-plan.md).
// Everything here exists in Go's stdlib and in browser WebCrypto, so the portal can
// implement the same bytes: X25519, HKDF-SHA256, AES-256-GCM, PKCS#8. The test vectors in
// testdata/securenet_vectors.json pin the formats for the TypeScript implementation.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Purpose labels for wrap v1. Each use has its own, so a wrap made for one purpose can
// never be opened as another.
const (
	PurposeAccountKeyToDevice = "share2us/secure-sharenet/ak-to-device/v1"
	PurposeEpochKeyToAccount  = "share2us/secure-sharenet/ek-to-ak/v1"
	recoveryInfo              = "share2us/secure-sharenet/recovery/v1"
)

var ErrSecureNetOpen = errors.New("secure sharenet: cannot open (wrong key, tampered, or wrong context)")

// Wrapped is a wrap v1 envelope: ephemeral X25519 public key, AES-GCM nonce, ciphertext.
type Wrapped struct {
	Eph   []byte `json:"eph"`
	Nonce []byte `json:"nonce"`
	CT    []byte `json:"ct"`
}

// WrapV1 seals payload from sender to recipient, authenticated (HPKE auth-mode style):
//
//	ikm  = X25519(eph, recipient) || X25519(sender, recipient)
//	salt = eph_pub || sender_pub || recipient_pub
//	key  = HKDF-SHA256(ikm, salt, info = purpose)
//	ct   = AES-256-GCM(key, nonce, payload, aad)
//
// Only the holder of the sender's private key can produce a wrap the recipient opens
// with the sender's public key, so a server that knows public keys can't forge one. aad
// binds the context (sharenet, epoch, account), so a wrap can't be moved to another.
func WrapV1(sender *ecdh.PrivateKey, recipientPub, payload []byte, purpose string, aad []byte) (Wrapped, error) {
	return wrapV1(rand.Reader, sender, recipientPub, payload, purpose, aad)
}

func wrapV1(rnd io.Reader, sender *ecdh.PrivateKey, recipientPub, payload []byte, purpose string, aad []byte) (Wrapped, error) {
	if sender == nil {
		return Wrapped{}, errors.New("wrap v1: sender key is required")
	}
	recipient, err := ecdh.X25519().NewPublicKey(recipientPub)
	if err != nil {
		return Wrapped{}, fmt.Errorf("recipient public key: %w", err)
	}
	eph, err := ecdh.X25519().GenerateKey(rnd)
	if err != nil {
		return Wrapped{}, err
	}
	dhE, err := eph.ECDH(recipient)
	if err != nil {
		return Wrapped{}, err
	}
	dhS, err := sender.ECDH(recipient)
	if err != nil {
		return Wrapped{}, err
	}
	key, err := wrapKey(append(dhE, dhS...), eph.PublicKey().Bytes(), sender.PublicKey().Bytes(), recipientPub, purpose)
	if err != nil {
		return Wrapped{}, err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rnd, nonce); err != nil {
		return Wrapped{}, err
	}
	ct, err := gcmSeal(key, nonce, payload, aad)
	if err != nil {
		return Wrapped{}, err
	}
	return Wrapped{Eph: eph.PublicKey().Bytes(), Nonce: nonce, CT: ct}, nil
}

// UnwrapV1 opens a wrap v1 envelope that senderPub made for recipient. Any malformed,
// tampered, mis-addressed or forged envelope returns ErrSecureNetOpen (never a panic:
// the envelope comes from the server and is untrusted).
func UnwrapV1(recipient *ecdh.PrivateKey, senderPub []byte, w Wrapped, purpose string, aad []byte) ([]byte, error) {
	if recipient == nil || len(w.Eph) != 32 || len(w.Nonce) != 12 || len(w.CT) < 16 || len(senderPub) != 32 {
		return nil, ErrSecureNetOpen
	}
	eph, err := ecdh.X25519().NewPublicKey(w.Eph)
	if err != nil {
		return nil, ErrSecureNetOpen
	}
	sender, err := ecdh.X25519().NewPublicKey(senderPub)
	if err != nil {
		return nil, ErrSecureNetOpen
	}
	dhE, err := recipient.ECDH(eph)
	if err != nil {
		return nil, ErrSecureNetOpen
	}
	dhS, err := recipient.ECDH(sender)
	if err != nil {
		return nil, ErrSecureNetOpen
	}
	key, err := wrapKey(append(dhE, dhS...), w.Eph, senderPub, recipient.PublicKey().Bytes(), purpose)
	if err != nil {
		return nil, err
	}
	pt, err := gcmOpen(key, w.Nonce, w.CT, aad)
	if err != nil {
		return nil, ErrSecureNetOpen
	}
	return pt, nil
}

func wrapKey(ikm, ephPub, senderPub, recipientPub []byte, purpose string) ([]byte, error) {
	salt := make([]byte, 0, len(ephPub)+len(senderPub)+len(recipientPub))
	salt = append(append(append(salt, ephPub...), senderPub...), recipientPub...)
	return hkdf.Key(sha256.New, ikm, salt, purpose, 32)
}

// NewAccountKey makes an account's X25519 key. MarshalAccountKey/ParseAccountKey move
// its private half as PKCS#8, the format WebCrypto can unwrapKey non-extractable.
func NewAccountKey() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }

func MarshalAccountKey(k *ecdh.PrivateKey) ([]byte, error) { return x509.MarshalPKCS8PrivateKey(k) }

func ParseAccountKey(pkcs8 []byte) (*ecdh.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	ek, ok := k.(*ecdh.PrivateKey)
	if !ok || ek.Curve() != ecdh.X25519() {
		return nil, errors.New("account key: not an X25519 key")
	}
	return ek, nil
}

// DeviceECDHKey turns an existing CLI/GUI device private key (NaCl box, raw Curve25519)
// into the X25519 key wrap v1 uses: the same curve, the same 32 bytes.
func DeviceECDHKey(raw []byte) (*ecdh.PrivateKey, error) { return ecdh.X25519().NewPrivateKey(raw) }

var recoveryEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewRecoveryCode returns 128 random bits as 26 base32 characters in groups of five
// (e.g. "ABCDE-FGHIJ-..."). 128 random bits need no slow KDF; HKDF is enough.
func NewRecoveryCode() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return formatRecovery(b), nil
}

func formatRecovery(b []byte) string {
	s := recoveryEnc.EncodeToString(b)
	var groups []string
	for len(s) > 5 {
		groups, s = append(groups, s[:5]), s[5:]
	}
	return strings.Join(append(groups, s), "-")
}

// RecoveryKey derives the AES key a recovery code wraps the account key under. Input is
// forgiving: case, spaces and dashes are ignored, and 0/1/8 read as O/I/B.
func RecoveryKey(code string) ([]byte, error) {
	c := strings.ToUpper(code)
	c = strings.NewReplacer("-", "", " ", "", "0", "O", "1", "I", "8", "B").Replace(c)
	raw, err := recoveryEnc.DecodeString(c)
	// Exact round trip: 128 bits leave 2 spare bits in the last character, which Go's
	// decoder ignores; requiring re-encoding to match keeps one code per key and lets a
	// strict browser decoder agree with Go.
	if err != nil || len(raw) != 16 || recoveryEnc.EncodeToString(raw) != c {
		return nil, errors.New("recovery code: not a valid code")
	}
	return hkdf.Key(sha256.New, raw, nil, recoveryInfo, 32)
}

// SealSym / OpenSym: AES-256-GCM with a random nonce, output nonce||ciphertext. The AAD
// names the context (see the *AAD helpers) so a wrap can't be moved to another sharenet,
// epoch or file.
func SealSym(key, plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct, err := gcmSeal(key, nonce, plaintext, aad)
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

func OpenSym(key, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < 12+16 {
		return nil, ErrSecureNetOpen
	}
	pt, err := gcmOpen(key, sealed[:12], sealed[12:], aad)
	if err != nil {
		return nil, ErrSecureNetOpen
	}
	return pt, nil
}

// Context strings for SealSym's AAD.
func EpochChainAAD(sharenetID string, epoch int) []byte {
	return []byte("share2us/secure-sharenet/epoch-chain/v1|" + sharenetID + "|" + strconv.Itoa(epoch))
}

// fileID is the file's stable id (its object key, known before upload), so a file key or
// name can't be swapped onto another file of the same epoch.
func FileKeyAAD(sharenetID string, epoch int, fileID string) []byte {
	return []byte("share2us/secure-sharenet/file-key/v1|" + sharenetID + "|" + strconv.Itoa(epoch) + "|" + fileID)
}
func FileNameAAD(sharenetID string, epoch int, fileID string) []byte {
	return []byte("share2us/secure-sharenet/file-name/v1|" + sharenetID + "|" + strconv.Itoa(epoch) + "|" + fileID)
}

// EpochKeyAAD binds an epoch key wrapped to an account to its sharenet, epoch and
// recipient account, so the server can't hand it out as another sharenet's or epoch's.
func EpochKeyAAD(sharenetID string, epoch int, accountID string) []byte {
	return []byte("share2us/secure-sharenet/epoch-key/v1|" + sharenetID + "|" + strconv.Itoa(epoch) + "|" + accountID)
}

// DeviceWrapAAD binds an account key wrapped to a device to the account and device.
func DeviceWrapAAD(accountID, deviceID string) []byte {
	return []byte("share2us/secure-sharenet/ak-to-device/v1|" + accountID + "|" + deviceID)
}
func RecoveryAAD(accountID string) []byte {
	return []byte("share2us/secure-sharenet/recovery-wrap/v1|" + accountID)
}

func gcmSeal(key, nonce, pt, aad []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return g.Seal(nil, nonce, pt, aad), nil
}

func gcmOpen(key, nonce, ct, aad []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, ct, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
