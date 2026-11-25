package clicore

// Secure ShareNet group keys on a device (ADR-051 option A, milestone 3): reading the epoch
// keys this account holds, rotating them, handing them to members who are waiting, and
// sealing / opening a file's key and name. The server only ever sees ciphertext.

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
)

var (
	ErrNotSecureSharenet = errors.New("not a Secure ShareNet")
	ErrNoEpochKeyHere    = errors.New("this account doesn't hold the sharenet's current key yet; a member's device hands it over when it next runs (or ask them to run 's2u keys sync')")
)

type SecureMember struct {
	AccountID string `json:"account_id"`
	PublicKey []byte `json:"public_key,omitempty"`
}

type EpochWrap struct {
	Epoch              int     `json:"epoch"`
	Wrapped            Wrapped `json:"wrapped"`
	WrappedByAccountID string  `json:"wrapped_by_account_id"`
	WrappedByPublicKey []byte  `json:"wrapped_by_public_key,omitempty"`
}

type ChainLink struct {
	Epoch     int    `json:"epoch"`
	ChainWrap []byte `json:"chain_wrap"`
}

type SecureState struct {
	Secure        bool           `json:"secure"`
	CurrentEpoch  int            `json:"current_epoch"`
	NeedsRotation bool           `json:"needs_rotation"`
	Members       []SecureMember `json:"members"`
	MyWraps       []EpochWrap    `json:"my_wraps"`
	Chain         []ChainLink    `json:"chain"`
	Pending       []SecureMember `json:"pending"`
}

type SharenetSummary struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Role   string `json:"role"`
	Secure bool   `json:"secure"`
}

type SharenetProject struct {
	ID         string `json:"id"`
	SharenetID string `json:"sharenet_id"`
	Name       string `json:"name"`
}

type SharenetFile struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ContentType  string `json:"content_type"`
	SizeBytes    int64  `json:"size_bytes"`
	PostedAt     string `json:"posted_at"`
	ProjectID    string `json:"project_id,omitempty"`
	PostedByName string `json:"posted_by_name"`
	Yours        bool   `json:"yours"`
	SecureEpoch  int    `json:"secure_epoch,omitempty"`
	FileKeyWrap  []byte `json:"file_key_wrap,omitempty"`
	FileNameCT   []byte `json:"file_name_ct,omitempty"`
	SecureFileID string `json:"secure_file_id,omitempty"`
}

type SharenetFileDownload struct {
	URL          string `json:"url"`
	Name         string `json:"name"`
	SecureEpoch  int    `json:"secure_epoch,omitempty"`
	FileKeyWrap  []byte `json:"file_key_wrap,omitempty"`
	FileNameCT   []byte `json:"file_name_ct,omitempty"`
	SecureFileID string `json:"secure_file_id,omitempty"`
}

func (c *Client) ListSharenets(ctx context.Context) ([]SharenetSummary, error) {
	var out struct {
		Sharenets []SharenetSummary `json:"sharenets"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v1/sharenets", nil, &out)
	return out.Sharenets, err
}

func (c *Client) ListSharenetProjects(ctx context.Context, sharenetID string) ([]SharenetProject, error) {
	var out struct {
		Projects []SharenetProject `json:"projects"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v1/sharenets/"+url.PathEscape(sharenetID)+"/projects", nil, &out)
	return out.Projects, err
}

func (c *Client) ListSharenetFiles(ctx context.Context, sharenetID string) ([]SharenetFile, error) {
	var out struct {
		Files []SharenetFile `json:"files"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v1/sharenets/"+url.PathEscape(sharenetID)+"/files", nil, &out)
	return out.Files, err
}

func (c *Client) SharenetFileDownload(ctx context.Context, sharenetID, fileID string) (SharenetFileDownload, error) {
	var out SharenetFileDownload
	err := c.doJSON(ctx, http.MethodGet, "/v1/sharenets/"+url.PathEscape(sharenetID)+"/files/"+url.PathEscape(fileID)+"/download", nil, &out)
	return out, err
}

func (c *Client) SecureState(ctx context.Context, sharenetID string) (SecureState, error) {
	var out SecureState
	err := c.doJSON(ctx, http.MethodGet, "/v1/sharenets/"+url.PathEscape(sharenetID)+"/secure", nil, &out)
	return out, err
}

// SharenetForProject finds the sharenet a project belongs to among the caller's sharenets
// (secure ones only when secureOnly), without telling the server what is being posted.
func (c *Client) SharenetForProject(ctx context.Context, projectID string, secureOnly bool) (SharenetSummary, bool, error) {
	nets, err := c.ListSharenets(ctx)
	if err != nil {
		return SharenetSummary{}, false, err
	}
	for _, n := range nets {
		if secureOnly && !n.Secure {
			continue
		}
		projects, err := c.ListSharenetProjects(ctx, n.ID)
		if err != nil {
			return SharenetSummary{}, false, err
		}
		for _, p := range projects {
			if p.ID == projectID {
				return n, true, nil
			}
		}
	}
	return SharenetSummary{}, false, nil
}

type wrapTo struct {
	Wrapped
	RecipientPublicKey []byte `json:"recipient_public_key"`
}

// SecureNet does the group-key work for one account on this device.
type SecureNet struct {
	Keys *Keyring
	Pins *PinStore
	ak   *ecdh.PrivateKey
}

func (s *SecureNet) accountKey(ctx context.Context) (*ecdh.PrivateKey, error) {
	if s.ak != nil {
		return s.ak, nil
	}
	ak, err := s.Keys.AccountKey(ctx)
	if err != nil {
		return nil, err
	}
	s.ak = ak
	return ak, nil
}

// checkKey applies TOFU to another account's key; this account's own key must be the one
// this device holds.
func (s *SecureNet) checkKey(accountID string, pub, mine []byte) error {
	if accountID == s.Keys.AccountID {
		if !bytes.Equal(pub, mine) {
			return &KeyChangedError{AccountID: accountID, Fingerprint: KeyFingerprint(accountID, pub)}
		}
		return nil
	}
	return s.Pins.Check(accountID, pub)
}

// EpochKeys opens every epoch key this account can reach: its own wraps, then older epochs
// down the chain. A wrap from a key this device doesn't trust is skipped.
func (s *SecureNet) EpochKeys(ctx context.Context, sharenetID string, st SecureState) (map[int][]byte, error) {
	ak, err := s.accountKey(ctx)
	if err != nil {
		return nil, err
	}
	mine := ak.PublicKey().Bytes()
	keys := map[int][]byte{}
	var firstErr error
	for _, w := range st.MyWraps {
		if err := s.checkKey(w.WrappedByAccountID, w.WrappedByPublicKey, mine); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ek, err := UnwrapV1(ak, w.WrappedByPublicKey, w.Wrapped, PurposeEpochKeyToAccount, EpochKeyAAD(sharenetID, w.Epoch, s.Keys.AccountID))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		keys[w.Epoch] = ek
	}
	links := append([]ChainLink(nil), st.Chain...)
	sort.Slice(links, func(i, j int) bool { return links[i].Epoch > links[j].Epoch })
	for _, l := range links {
		newer, ok := keys[l.Epoch]
		if !ok || keys[l.Epoch-1] != nil {
			continue
		}
		older, err := OpenSym(newer, l.ChainWrap, EpochChainAAD(sharenetID, l.Epoch-1))
		if err != nil {
			continue
		}
		keys[l.Epoch-1] = older
	}
	if len(keys) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return keys, nil
}

func (s *SecureNet) wrapsTo(sharenetID string, epoch int, ek []byte, ak *ecdh.PrivateKey, members []SecureMember) (map[string]wrapTo, error) {
	mine := ak.PublicKey().Bytes()
	out := map[string]wrapTo{}
	for _, m := range members {
		if len(m.PublicKey) == 0 {
			continue // not enrolled yet; they become pending when they do
		}
		if err := s.checkKey(m.AccountID, m.PublicKey, mine); err != nil {
			return nil, err
		}
		w, err := WrapV1(ak, m.PublicKey, ek, PurposeEpochKeyToAccount, EpochKeyAAD(sharenetID, epoch, m.AccountID))
		if err != nil {
			return nil, err
		}
		out[m.AccountID] = wrapTo{Wrapped: w, RecipientPublicKey: m.PublicKey}
	}
	return out, nil
}

// Rotate starts the next epoch: the sharenet's first key, or a new one after someone left.
// It chains the current key in when this account holds it. Without it, restart (owner or
// manager only, and only when nobody left can open the current key) begins a fresh chain:
// files from before can't be read through it.
func (s *SecureNet) Rotate(ctx context.Context, sharenetID string, restart bool) (int, error) {
	st, err := s.Keys.Client.SecureState(ctx, sharenetID)
	if err != nil {
		return 0, err
	}
	if !st.Secure {
		return 0, ErrNotSecureSharenet
	}
	ak, err := s.accountKey(ctx)
	if err != nil {
		return 0, err
	}
	next := st.CurrentEpoch + 1
	var chain []byte
	ek, err := NewDataKey()
	if err != nil {
		return 0, err
	}
	if st.CurrentEpoch > 0 {
		keys, err := s.EpochKeys(ctx, sharenetID, st)
		if err != nil && !restart {
			return 0, err
		}
		if cur, ok := keys[st.CurrentEpoch]; ok {
			if chain, err = SealSym(ek, cur, EpochChainAAD(sharenetID, st.CurrentEpoch)); err != nil {
				return 0, err
			}
		} else if !restart {
			return 0, ErrNoEpochKeyHere
		}
	}
	wraps, err := s.wrapsTo(sharenetID, next, ek, ak, st.Members)
	if err != nil {
		return 0, err
	}
	req := map[string]any{"epoch": next, "sender_public_key": ak.PublicKey().Bytes(), "wraps": wraps}
	if chain != nil {
		req["chain_wrap"] = chain
	}
	if err := s.Keys.Client.doJSON(ctx, http.MethodPost, "/v1/sharenets/"+url.PathEscape(sharenetID)+"/epochs", req, nil); err != nil {
		return 0, err
	}
	return next, nil
}

// HandOver wraps the current epoch key to every member who is waiting for it. Members
// whose key changed are skipped and reported (the user must trust them first).
func (s *SecureNet) HandOver(ctx context.Context, sharenetID string) (int, []error, error) {
	st, err := s.Keys.Client.SecureState(ctx, sharenetID)
	if err != nil {
		return 0, nil, err
	}
	if !st.Secure || st.CurrentEpoch == 0 || len(st.Pending) == 0 {
		return 0, nil, nil
	}
	keys, err := s.EpochKeys(ctx, sharenetID, st)
	if err != nil {
		return 0, nil, err
	}
	ek, ok := keys[st.CurrentEpoch]
	if !ok {
		return 0, nil, nil // someone else will; this account can't
	}
	ak, err := s.accountKey(ctx)
	if err != nil {
		return 0, nil, err
	}
	var skipped []error
	var ready []SecureMember
	for _, m := range st.Pending {
		if err := s.checkKey(m.AccountID, m.PublicKey, ak.PublicKey().Bytes()); err != nil {
			skipped = append(skipped, err)
			continue
		}
		ready = append(ready, m)
	}
	if len(ready) == 0 {
		return 0, skipped, nil
	}
	wraps, err := s.wrapsTo(sharenetID, st.CurrentEpoch, ek, ak, ready)
	if err != nil {
		return 0, skipped, err
	}
	var out struct {
		Added int `json:"added"`
	}
	req := map[string]any{"epoch": st.CurrentEpoch, "sender_public_key": ak.PublicKey().Bytes(), "wraps": wraps}
	if err := s.Keys.Client.doJSON(ctx, http.MethodPost, "/v1/sharenets/"+url.PathEscape(sharenetID)+"/epoch-wraps", req, &out); err != nil {
		return 0, skipped, err
	}
	return out.Added, skipped, nil
}

// SealedPost is what a secure post sends instead of plaintext metadata. DataKey encrypts
// the content (EncryptStream) and is never sent.
type SealedPost struct {
	Epoch       int
	FileID      string
	FileKeyWrap []byte
	FileNameCT  []byte
	DataKey     []byte
}

// PreparePost seals a new file's key and name under the current epoch key, creating the
// first key or rotating first when the sharenet needs it.
func (s *SecureNet) PreparePost(ctx context.Context, sharenetID, fileName string) (SealedPost, error) {
	st, err := s.Keys.Client.SecureState(ctx, sharenetID)
	if err != nil {
		return SealedPost{}, err
	}
	if !st.Secure {
		return SealedPost{}, ErrNotSecureSharenet
	}
	if st.CurrentEpoch == 0 || st.NeedsRotation {
		if _, err := s.Rotate(ctx, sharenetID, false); err != nil {
			return SealedPost{}, fmt.Errorf("rotate the sharenet key: %w", err)
		}
		if st, err = s.Keys.Client.SecureState(ctx, sharenetID); err != nil {
			return SealedPost{}, err
		}
	}
	keys, err := s.EpochKeys(ctx, sharenetID, st)
	if err != nil {
		return SealedPost{}, err
	}
	ek, ok := keys[st.CurrentEpoch]
	if !ok {
		return SealedPost{}, ErrNoEpochKeyHere
	}
	idRaw := make([]byte, 16)
	if _, err := rand.Read(idRaw); err != nil {
		return SealedPost{}, err
	}
	p := SealedPost{Epoch: st.CurrentEpoch, FileID: base64.RawURLEncoding.EncodeToString(idRaw)}
	if p.DataKey, err = NewDataKey(); err != nil {
		return SealedPost{}, err
	}
	if p.FileKeyWrap, err = SealSym(ek, p.DataKey, FileKeyAAD(sharenetID, p.Epoch, p.FileID)); err != nil {
		return SealedPost{}, err
	}
	if p.FileNameCT, err = SealSym(ek, []byte(fileName), FileNameAAD(sharenetID, p.Epoch, p.FileID)); err != nil {
		return SealedPost{}, err
	}
	return p, nil
}

// OpenFile returns a secure file's content key and real name.
func (s *SecureNet) OpenFile(ctx context.Context, sharenetID string, epoch int, fileID string, keyWrap, nameCT []byte) ([]byte, string, error) {
	st, err := s.Keys.Client.SecureState(ctx, sharenetID)
	if err != nil {
		return nil, "", err
	}
	keys, err := s.EpochKeys(ctx, sharenetID, st)
	if err != nil {
		return nil, "", err
	}
	ek, ok := keys[epoch]
	if !ok {
		return nil, "", fmt.Errorf("this account can't open epoch %d of the sharenet (it was posted before a key restart, or the key hasn't been handed to you yet)", epoch)
	}
	dk, err := OpenSym(ek, keyWrap, FileKeyAAD(sharenetID, epoch, fileID))
	if err != nil {
		return nil, "", err
	}
	name, err := OpenSym(ek, nameCT, FileNameAAD(sharenetID, epoch, fileID))
	if err != nil {
		return nil, "", err
	}
	return dk, string(name), nil
}
