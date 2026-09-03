package lanid

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ADR-034: the trusted-device list lives on the account and is signed by the
// server. This file is the client-side cache of that signed list. It is the ONLY
// source Lookup/List read; a hand-edited or unsigned file is ignored, so trust
// cannot be widened locally (by a user, or by an agent driving the CLI).

// SignedTrustList is the server's signed list as returned by GET /v1/lan/trusted
// (and by the challenge verify / mode / revoke endpoints).
type SignedTrustList struct {
	KeyID     string `json:"kid"`
	Payload   string `json:"payload"`   // base64url JSON of TrustListPayload
	Signature string `json:"signature"` // base64url Ed25519 over the raw payload
}

// TrustListPayload is the signed content.
type TrustListPayload struct {
	Version   int             `json:"v"`
	AccountID string          `json:"account_id"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Devices   []TrustedDevice `json:"devices"`
}

type signedTrustFile struct {
	PublicKey string          `json:"public_key"` // pinned on first save
	List      SignedTrustList `json:"list"`
	FetchedAt time.Time       `json:"fetched_at"`
}

var (
	// ErrTrustKeyChanged means the server presented a different signing key than
	// the one pinned locally. Refused rather than silently re-pinned; the user
	// clears the cache (ResetTrust) if the server really rotated its key.
	ErrTrustKeyChanged = errors.New("lanid: server trust-signing key changed; run `lan trusted reset` if this is expected")
	// ErrLocalTrustDisabled is returned by the retired local writers.
	ErrLocalTrustDisabled = errors.New("lanid: trusting a device requires verification through your account (ADR-034); local trust is disabled")

	signedMu sync.Mutex
)

func signedTrustPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "lan_trusted_signed.json"), nil
}

// VerifyTrustList checks a signed list against a public key (hex) at time now.
func VerifyTrustList(list SignedTrustList, publicKeyHex string, now time.Time) (TrustListPayload, error) {
	pub, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return TrustListPayload{}, errors.New("lanid: bad trust public key")
	}
	raw, err := base64.RawURLEncoding.DecodeString(list.Payload)
	if err != nil {
		return TrustListPayload{}, fmt.Errorf("lanid: trust payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(list.Signature)
	if err != nil {
		return TrustListPayload{}, fmt.Errorf("lanid: trust signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), raw, sig) {
		return TrustListPayload{}, errors.New("lanid: trust list signature does not verify")
	}
	var p TrustListPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return TrustListPayload{}, err
	}
	if !now.Before(p.ExpiresAt) {
		return TrustListPayload{}, errors.New("lanid: trust list expired")
	}
	return p, nil
}

// SaveSignedTrust verifies a freshly fetched list and caches it. The server key
// is pinned on the first save; a different key later is refused.
func SaveSignedTrust(list SignedTrustList, publicKeyHex string) error {
	if _, err := VerifyTrustList(list, publicKeyHex, time.Now()); err != nil {
		return err
	}
	p, err := signedTrustPath()
	if err != nil {
		return err
	}
	signedMu.Lock()
	defer signedMu.Unlock()
	if prev, ok := readSignedFile(p); ok && prev.PublicKey != "" && prev.PublicKey != publicKeyHex {
		return ErrTrustKeyChanged
	}
	data, err := json.MarshalIndent(signedTrustFile{PublicKey: publicKeyHex, List: list, FetchedAt: time.Now().UTC()}, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// ResetTrust drops the cached list and the pinned key.
func ResetTrust() error {
	p, err := signedTrustPath()
	if err != nil {
		return err
	}
	signedMu.Lock()
	defer signedMu.Unlock()
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// PinnedTrustKey returns the pinned server key ("" if none yet).
func PinnedTrustKey() string {
	p, err := signedTrustPath()
	if err != nil {
		return ""
	}
	signedMu.Lock()
	defer signedMu.Unlock()
	f, ok := readSignedFile(p)
	if !ok {
		return ""
	}
	return f.PublicKey
}

func readSignedFile(path string) (signedTrustFile, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return signedTrustFile{}, false
	}
	var f signedTrustFile
	if json.Unmarshal(data, &f) != nil {
		return signedTrustFile{}, false
	}
	return f, true
}

// cachedDevices returns the verified devices from the cache (nil when there is
// no valid cache: missing, tampered or expired).
func cachedDevices(now time.Time) []TrustedDevice {
	p, err := signedTrustPath()
	if err != nil {
		return nil
	}
	signedMu.Lock()
	f, ok := readSignedFile(p)
	signedMu.Unlock()
	if !ok {
		return nil
	}
	payload, err := VerifyTrustList(f.List, f.PublicKey, now)
	if err != nil {
		return nil
	}
	return payload.Devices
}

// TrustCacheStatus reports whether a verified cache exists and when it expires.
func TrustCacheStatus() (ok bool, expires time.Time) {
	p, err := signedTrustPath()
	if err != nil {
		return false, time.Time{}
	}
	signedMu.Lock()
	f, found := readSignedFile(p)
	signedMu.Unlock()
	if !found {
		return false, time.Time{}
	}
	payload, err := VerifyTrustList(f.List, f.PublicKey, time.Now())
	if err != nil {
		return false, time.Time{}
	}
	return true, payload.ExpiresAt
}
