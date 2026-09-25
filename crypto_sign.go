package clicore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Signed hops (ADR-041 §5, questionnaire Q120/Q121).
//
// WHY THIS EXISTS. Prompts to an agent are sealed with box.SealAnonymous, which
// makes them confidential — only the receiving device can open one — but says
// nothing about who wrote it. Anyone who knows a device's public key can seal a
// prompt to it, and those keys are published in the agent session directory. So
// until now the SERVER was the only thing vouching for a hop's sender: it checks
// the sender's bearer token and the consent grant. A compromised server, or
// anything that can write to its queue, could inject a prompt the daemon would
// unseal and run.
//
// A signature moves that guarantee to the ends. The sender signs a hop with a
// device signing key; the server verifies it before anything is stored, which
// catches a forgery at the edge; and the RECEIVING daemon verifies it again
// against the key it pinned when it first approved that sender. The second check
// is the one that matters: server-side verification cannot defend against a
// compromised server, but a pinned key can.
//
// Ed25519 rather than authenticated box encryption, deliberately. Box would reuse
// the existing X25519 keys, but only the receiver could verify it and it is
// repudiable (either party can produce a valid message). Ed25519 lets the server
// reject forgeries before they are queued and gives the audit log a
// non-repudiable record of who sent what (Q126).

// hopSigningDomain separates a hop signature from any other signature the same
// key might ever produce. A signature is only ever valid for the purpose it was
// made for.
const hopSigningDomain = "share2us/agent-hop/v1"

// ErrHopSignature covers every way a hop signature can fail: wrong key, altered
// field, malformed signature. Callers should not distinguish them to a remote
// party — "this hop is not authentic" is the whole answer.
var ErrHopSignature = errors.New("hop signature is not valid")

// ErrHopStale is a valid signature outside the freshness window: a replay, or a
// clock far enough out that it cannot be told apart from one.
var ErrHopStale = errors.New("hop signature is outside the freshness window")

// SigningKeyPair is a device's Ed25519 signing identity, base64-encoded like the
// existing device encryption keys. It is separate from the X25519 key pair:
// reusing one key for both encryption and signing is a classic way to get a
// cross-protocol attack, and the two have different lifetimes anyway.
type SigningKeyPair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// NewSigningKeyPair creates a fresh device signing key.
func NewSigningKeyPair() (SigningKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SigningKeyPair{}, err
	}
	return SigningKeyPair{
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	}, nil
}

// HopClaims is everything a hop's signature covers. Anything that changes what
// the receiver does or where the hop goes is here, so that none of it can be
// rewritten in transit:
//
//   - who sent it, and to which device, session and tool (so a hop cannot be
//     redirected to a different agent);
//   - the sealed prompt, and the attachment's sealed content key (so neither can
//     be swapped — see below for why the key rather than the object);
//   - the goal it is counted against (so it cannot be moved onto another budget);
//   - when it was issued and a nonce (so it cannot be replayed, Q121).
//
// The attachment is bound by its SEALED CONTENT KEY, not by its storage object
// key, and that is deliberate. The receiver is never given the object key — it
// downloads by request id, so bucket paths do not leak to clients — which means a
// signature over the object key could not be checked by the one party whose check
// matters. It does not need to be: the file is encrypted with an AEAD under that
// content key, the key is sealed to the receiver and covered here, so a server
// that swaps in a different object gets a decryption failure, not a substitution.
type HopClaims struct {
	SenderDeviceID  string
	TargetDeviceID  string
	TargetSessionID string
	Tool            string
	SealedPrompt    string
	SealedFileKey   string
	GoalID          string
	IssuedAt        time.Time
	Nonce           string
}

// SigningBytes is the exact byte string a hop signature covers.
//
// Every field is length-prefixed, in a fixed order, after a domain tag. That
// makes the encoding unambiguous: with a delimiter instead, ("ab","c") and
// ("a","bc") could serialize identically and one signature would cover both. The
// time is whole Unix seconds, so the bytes do not depend on how either side
// formats or rounds a timestamp.
func (c HopClaims) SigningBytes() []byte {
	fields := []string{
		c.SenderDeviceID,
		c.TargetDeviceID,
		c.TargetSessionID,
		c.Tool,
		c.SealedPrompt,
		c.SealedFileKey,
		c.GoalID,
		fmt.Sprintf("%d", c.IssuedAt.Unix()),
		c.Nonce,
	}
	size := 4 + len(hopSigningDomain)
	for _, f := range fields {
		size += 4 + len(f)
	}
	out := make([]byte, 0, size)
	out = appendField(out, hopSigningDomain)
	for _, f := range fields {
		out = appendField(out, f)
	}
	return out
}

func appendField(buf []byte, field string) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(field)))
	buf = append(buf, n[:]...)
	return append(buf, field...)
}

// NewHopNonce returns a random nonce for HopClaims.Nonce.
func NewHopNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SignHop signs a hop with a device's private signing key.
func SignHop(c HopClaims, privateKey string) (string, error) {
	priv, err := decodeSigningPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, c.SigningBytes())), nil
}

// VerifyHop checks a hop's signature against the sender's public signing key.
// It does not check freshness; use VerifyHopFresh on the paths that must refuse
// a replay, which is all of them that act on a hop.
func VerifyHop(c HopClaims, signature, publicKey string) error {
	pub, err := decodeSigningPublicKey(publicKey)
	if err != nil {
		return ErrHopSignature
	}
	sig, err := decodeFlexibleBase64(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrHopSignature
	}
	if !ed25519.Verify(pub, c.SigningBytes(), sig) {
		return ErrHopSignature
	}
	return nil
}

// VerifyHopFresh is VerifyHop plus a freshness window around now. A hop issued
// too long ago is refused as a replay, and one issued too far in the future is
// refused too — otherwise a sender with a skewed clock (or an attacker) could mint
// hops that stay "fresh" for as long as they like.
//
// The signature is checked FIRST, so an attacker cannot learn anything about the
// window by sending unsigned hops with chosen timestamps.
func VerifyHopFresh(c HopClaims, signature, publicKey string, now time.Time, window time.Duration) error {
	if err := VerifyHop(c, signature, publicKey); err != nil {
		return err
	}
	age := now.Sub(c.IssuedAt)
	if age > window || age < -window {
		return ErrHopStale
	}
	return nil
}

func decodeSigningPublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := decodeFlexibleBase64(encoded)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, ErrInvalidKey
	}
	return ed25519.PublicKey(raw), nil
}

func decodeSigningPrivateKey(encoded string) (ed25519.PrivateKey, error) {
	raw, err := decodeFlexibleBase64(encoded)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKey
	}
	return ed25519.PrivateKey(raw), nil
}
