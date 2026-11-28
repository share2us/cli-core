package clicore

// Secrets in agent DMs (ADR-054 phase 3). The DM's person seals a secret in the browser to
// the agent owner's account key with wrap v1 under a fresh, thrown-away sender key; the
// server stores only the envelope. The agent's machine (an approved device of the owner's
// account) fetches it with GET /v1/secrets/{id} and opens it with the account key.

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// PurposeDMSecret is the wrap v1 purpose (HKDF info) for a DM secret.
const PurposeDMSecret = "share2us/dm-secret/v1"

// MaxDMSecretPayload is the largest sealed payload (UTF-8 JSON) a DM secret may carry.
const MaxDMSecretPayload = 16 << 10

// DMSecretAAD binds a DM secret to its id, DM and recipient (owner) account, so the server
// can't move it to another DM or hand it to another account.
func DMSecretAAD(secretID, dmID, ownerAccountID string) []byte {
	return []byte(PurposeDMSecret + "|" + secretID + "|" + dmID + "|" + ownerAccountID)
}

// DMSecret is GET /v1/secrets/{id}. The byte fields arrive base64-encoded.
type DMSecret struct {
	ID                 string    `json:"id"`
	SharenetID         string    `json:"sharenet_id"`
	DMID               string    `json:"dm_id"`
	Label              string    `json:"label"`
	RecipientAccountID string    `json:"recipient_account_id"`
	SenderPub          []byte    `json:"sender_pub"`
	Eph                []byte    `json:"eph"`
	Nonce              []byte    `json:"nonce"`
	CT                 []byte    `json:"ct"`
	CreatedAt          time.Time `json:"created_at"`
}

// ErrDMSecretRemoved means the secret's envelope was wiped (DELETE /v1/secrets/{id}).
var ErrDMSecretRemoved = errors.New("this secret was removed by its sender or owner")

// GetDMSecret fetches a DM secret addressed to the caller's account (device auth). The
// server answers 404 for anyone but the owner.
func (c *Client) GetDMSecret(ctx context.Context, id string) (DMSecret, error) {
	var out DMSecret
	if id == "" {
		return out, errors.New("secret id is required")
	}
	err := c.doJSON(ctx, http.MethodGet, "/v1/secrets/"+url.PathEscape(id), nil, &out)
	return out, err
}

type dmSecretPayload struct {
	V     int    `json:"v"`
	Label string `json:"label"`
	Value string `json:"value"`
}

// OpenDMSecret opens s with the account key ak. The AAD is rebuilt from s's id, DM and
// recipient account, so an envelope served under another id or DM fails to open. Any
// malformed, tampered or mis-addressed envelope returns ErrSecureNetOpen.
func OpenDMSecret(ak *ecdh.PrivateKey, s DMSecret) (label, value string, err error) {
	if len(s.Eph) == 0 && len(s.Nonce) == 0 && len(s.CT) == 0 {
		return "", "", ErrDMSecretRemoved
	}
	pt, err := UnwrapV1(ak, s.SenderPub, Wrapped{Eph: s.Eph, Nonce: s.Nonce, CT: s.CT}, PurposeDMSecret, DMSecretAAD(s.ID, s.DMID, s.RecipientAccountID))
	if err != nil {
		return "", "", err
	}
	var p dmSecretPayload
	if err := json.Unmarshal(pt, &p); err != nil {
		return "", "", fmt.Errorf("dm secret: bad payload: %w", err)
	}
	if p.V != 1 {
		return "", "", fmt.Errorf("dm secret: unsupported payload version %d", p.V)
	}
	return p.Label, p.Value, nil
}

// SealDMSecret is the sender side (the portal does this in the browser): a fresh sender
// key per secret, wrap v1 to the owner's account public key. It returns a DMSecret with the
// envelope fields filled in, ready to POST or to serve in tests.
func SealDMSecret(ownerPub []byte, secretID, dmID, ownerAccountID, label, value string) (DMSecret, error) {
	pt, err := json.Marshal(dmSecretPayload{V: 1, Label: label, Value: value})
	if err != nil {
		return DMSecret{}, err
	}
	if len(pt) > MaxDMSecretPayload {
		return DMSecret{}, fmt.Errorf("dm secret: payload is %d bytes, the limit is %d", len(pt), MaxDMSecretPayload)
	}
	sender, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return DMSecret{}, err
	}
	w, err := WrapV1(sender, ownerPub, pt, PurposeDMSecret, DMSecretAAD(secretID, dmID, ownerAccountID))
	if err != nil {
		return DMSecret{}, err
	}
	return DMSecret{
		ID: secretID, DMID: dmID, Label: label, RecipientAccountID: ownerAccountID,
		SenderPub: sender.PublicKey().Bytes(), Eph: w.Eph, Nonce: w.Nonce, CT: w.CT,
	}, nil
}
