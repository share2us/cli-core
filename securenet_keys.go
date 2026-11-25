package clicore

// Secure ShareNet account keys on a device (ADR-051 option A, milestone 3). The account key
// (AK) is one X25519 key per account; this device holds it only wrapped to its device key,
// and the server holds it wrapped to the recovery code. Nothing here sends a private key.

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

var (
	ErrKeysNotEnrolled     = errors.New("this account has no Secure ShareNet key yet; run 's2u keys enrol'")
	ErrDeviceNotApproved   = errors.New("this device can't open the account key yet; approve it from an enrolled device ('s2u keys approve') or run 's2u keys recover'")
	ErrAccountKeyMismatch  = errors.New("the account key the server returned doesn't match the one it opened to; refusing it")
	ErrDeviceIDMismatch    = errors.New("the device key doesn't match its id; refusing to approve it")
	ErrRecoveryCodeInvalid = errors.New("that recovery code doesn't open this account's key")
)

// KeyDeviceID is the server's id for a device key: "k_" + base64url(sha256(pub))[:22].
// Clients derive it themselves so a server can't relabel a key.
func KeyDeviceID(pub []byte) string {
	sum := sha256.Sum256(pub)
	return "k_" + base64.RawURLEncoding.EncodeToString(sum[:])[:22]
}

type KeyDevice struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	PublicKey  []byte     `json:"public_key"`
	Approved   bool       `json:"approved"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type KeysStatus struct {
	Enrolled  bool        `json:"enrolled"`
	PublicKey []byte      `json:"public_key,omitempty"`
	Devices   []KeyDevice `json:"devices"`
}

type keyDeviceWrap struct {
	Approved         bool     `json:"approved"`
	DevicePublicKey  []byte   `json:"device_public_key"`
	Wrap             *Wrapped `json:"wrap,omitempty"`
	AccountPublicKey []byte   `json:"account_public_key"`
}

func (c *Client) KeysStatus(ctx context.Context) (KeysStatus, error) {
	var out KeysStatus
	err := c.doJSON(ctx, http.MethodGet, "/v1/keys", nil, &out)
	return out, err
}

func (c *Client) RemoveKeyDevice(ctx context.Context, deviceID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/keys/devices/"+url.PathEscape(deviceID), nil, nil)
}

// Keyring is this device's view of the account key.
type Keyring struct {
	Client    *Client
	AccountID string
	device    *ecdh.PrivateKey
}

// NewKeyring uses the device's existing X25519 private key (Credential.DevicePrivateKey).
func NewKeyring(c *Client, accountID, devicePrivateKey string) (*Keyring, error) {
	raw, err := decodeDeviceKey(devicePrivateKey)
	if err != nil {
		return nil, fmt.Errorf("device key: %w", err)
	}
	dk, err := DeviceECDHKey(raw)
	if err != nil {
		return nil, fmt.Errorf("device key: %w", err)
	}
	if accountID == "" {
		return nil, errors.New("account id is required")
	}
	return &Keyring{Client: c, AccountID: accountID, device: dk}, nil
}

func (k *Keyring) DevicePublicKey() []byte { return k.device.PublicKey().Bytes() }
func (k *Keyring) DeviceID() string        { return KeyDeviceID(k.DevicePublicKey()) }

func (k *Keyring) wrapToDevice(ak *ecdh.PrivateKey, devicePub []byte) (Wrapped, error) {
	pkcs8, err := MarshalAccountKey(ak)
	if err != nil {
		return Wrapped{}, err
	}
	return WrapV1(ak, devicePub, pkcs8, PurposeAccountKeyToDevice, DeviceWrapAAD(k.AccountID, KeyDeviceID(devicePub)))
}

// Enrol creates the account key, wraps it to this device and to a new recovery code, and
// uploads both. The returned code is shown to the user once and never stored; the public
// key is for the caller to pin as this account's own.
func (k *Keyring) Enrol(ctx context.Context, label string) (string, []byte, error) {
	ak, err := NewAccountKey()
	if err != nil {
		return "", nil, err
	}
	code, err := NewRecoveryCode()
	if err != nil {
		return "", nil, err
	}
	rk, err := RecoveryKey(code)
	if err != nil {
		return "", nil, err
	}
	pkcs8, err := MarshalAccountKey(ak)
	if err != nil {
		return "", nil, err
	}
	recWrap, err := SealSym(rk, pkcs8, RecoveryAAD(k.AccountID))
	if err != nil {
		return "", nil, err
	}
	devWrap, err := k.wrapToDevice(ak, k.DevicePublicKey())
	if err != nil {
		return "", nil, err
	}
	req := map[string]any{
		"public_key":    ak.PublicKey().Bytes(),
		"recovery_wrap": recWrap,
		"device":        map[string]any{"label": label, "public_key": k.DevicePublicKey(), "wrap": devWrap},
	}
	if err := k.Client.doJSON(ctx, http.MethodPost, "/v1/keys/enroll", req, nil); err != nil {
		return "", nil, err
	}
	return code, ak.PublicKey().Bytes(), nil
}

// RegisterDevice asks to join the account key; an enrolled device then approves it.
func (k *Keyring) RegisterDevice(ctx context.Context, label string) error {
	req := map[string]any{"label": label, "public_key": k.DevicePublicKey()}
	return k.Client.doJSON(ctx, http.MethodPost, "/v1/keys/devices", req, nil)
}

// AccountKey opens the account key wrapped to this device.
func (k *Keyring) AccountKey(ctx context.Context) (*ecdh.PrivateKey, error) {
	var d keyDeviceWrap
	err := k.Client.doJSON(ctx, http.MethodGet, "/v1/keys/devices/"+url.PathEscape(k.DeviceID()), nil, &d)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Code == "not_enrolled" {
		return nil, ErrKeysNotEnrolled
	}
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
		return nil, ErrDeviceNotApproved // not registered yet
	}
	if err != nil {
		return nil, err
	}
	if !d.Approved || d.Wrap == nil {
		return nil, ErrDeviceNotApproved
	}
	pkcs8, err := UnwrapV1(k.device, d.AccountPublicKey, *d.Wrap, PurposeAccountKeyToDevice, DeviceWrapAAD(k.AccountID, k.DeviceID()))
	if err != nil {
		return nil, err
	}
	ak, err := ParseAccountKey(pkcs8)
	if err != nil {
		return nil, err
	}
	// wrap v1 already proves the wrap came from the holder of d.AccountPublicKey; this
	// checks the key inside is that same key.
	if !bytes.Equal(ak.PublicKey().Bytes(), d.AccountPublicKey) {
		return nil, ErrAccountKeyMismatch
	}
	return ak, nil
}

// Recover opens the account key with the recovery code and approves this device with it.
func (k *Keyring) Recover(ctx context.Context, code, label string) ([]byte, error) {
	rk, err := RecoveryKey(code)
	if err != nil {
		return nil, ErrRecoveryCodeInvalid
	}
	var rec struct {
		PublicKey    []byte `json:"public_key"`
		RecoveryWrap []byte `json:"recovery_wrap"`
	}
	if err := k.Client.doJSON(ctx, http.MethodGet, "/v1/keys/recovery", nil, &rec); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
			return nil, ErrKeysNotEnrolled
		}
		return nil, err
	}
	pkcs8, err := OpenSym(rk, rec.RecoveryWrap, RecoveryAAD(k.AccountID))
	if err != nil {
		return nil, ErrRecoveryCodeInvalid
	}
	ak, err := ParseAccountKey(pkcs8)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(ak.PublicKey().Bytes(), rec.PublicKey) {
		return nil, ErrAccountKeyMismatch
	}
	if err := k.RegisterDevice(ctx, label); err != nil && !isConflict(err) {
		return nil, err
	}
	if err := k.approve(ctx, ak, k.DeviceID(), k.DevicePublicKey()); err != nil && !isConflict(err) {
		return nil, err // a conflict means this device was already approved
	}
	return ak.PublicKey().Bytes(), nil
}

// Approve gives another of this account's devices the account key (use
// SecureNet.ApproveDevice, which checks the key against this device's pin). The device's
// key is fetched from the server and must hash to deviceID, which the user compared.
func (k *Keyring) Approve(ctx context.Context, ak *ecdh.PrivateKey, deviceID string) error {
	var d keyDeviceWrap
	if err := k.Client.doJSON(ctx, http.MethodGet, "/v1/keys/devices/"+url.PathEscape(deviceID), nil, &d); err != nil {
		return err
	}
	if KeyDeviceID(d.DevicePublicKey) != deviceID {
		return ErrDeviceIDMismatch
	}
	return k.approve(ctx, ak, deviceID, d.DevicePublicKey)
}

func (k *Keyring) approve(ctx context.Context, ak *ecdh.PrivateKey, deviceID string, devicePub []byte) error {
	w, err := k.wrapToDevice(ak, devicePub)
	if err != nil {
		return err
	}
	return k.Client.doJSON(ctx, http.MethodPost, "/v1/keys/devices/"+url.PathEscape(deviceID)+"/approve", map[string]any{"wrap": w}, nil)
}

func isConflict(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict
}
