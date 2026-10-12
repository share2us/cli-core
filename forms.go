// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Interactive form shares (ADR-046). These read-side client calls let the form owner
// (and a submitter) list and fetch E2E-sealed responses; decryption happens locally with
// the device keypair via OpenFormResponse.

// FormResponseMeta is one row in the owner's Submissions list. SubmitterEmail is revealed
// to the owner by design (a form is the owner's own form).
type FormResponseMeta struct {
	ID             string    `json:"id"`
	SubmitterEmail string    `json:"submitter_email"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
}

// FormSealedKey binds a sealed content key to the device that can open it.
type FormSealedKey struct {
	DeviceSessionID string `json:"device_session_id"`
	SealedKey       string `json:"sealed_key"`
}

// FormResponsePayload is a sealed response body plus the sealed keys for the caller's own
// devices (the server filters to the reader's devices).
type FormResponsePayload struct {
	Ciphertext   string          `json:"ciphertext"`
	SealedKeys   []FormSealedKey `json:"sealed_keys"`
	WebSealedKey string          `json:"web_sealed_key,omitempty"`
}

// ListFormResponses returns the owner's Submissions page for a form share.
func (c *Client) ListFormResponses(ctx context.Context, formID string, limit, offset int) ([]FormResponseMeta, bool, error) {
	var out struct {
		Responses []FormResponseMeta `json:"responses"`
		HasMore   bool               `json:"has_more"`
	}
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	path := "/v1/forms/" + url.PathEscape(formID) + "/responses"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	err := c.doJSON(ctx, http.MethodGet, path, nil, &out)
	return out.Responses, out.HasMore, err
}

// GetFormResponse fetches one sealed response the caller is allowed to read.
func (c *Client) GetFormResponse(ctx context.Context, formID, responseID string) (FormResponsePayload, error) {
	var out FormResponsePayload
	path := "/v1/forms/" + url.PathEscape(formID) + "/responses/" + url.PathEscape(responseID)
	err := c.doJSON(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

// AccountWebKey is the portal web key (ADR-046 Phase 2): the X25519 public key plus the
// passphrase-wrapped private key (opaque; only the portal unwraps it) and its KDF params.
type AccountWebKey struct {
	PublicKey         string          `json:"public_key"`
	WrappedPrivateKey string          `json:"wrapped_private_key"`
	KDF               json.RawMessage `json:"kdf"`
}

// ResponseWebSeal is one re-sealed response: the content key sealed to the owner's web key.
type ResponseWebSeal struct {
	ResponseID string `json:"response_id"`
	SealedKey  string `json:"sealed_key"`
}

// GetAccountWebKey returns the caller's web key. ok is false (no error) when none is set.
func (c *Client) GetAccountWebKey(ctx context.Context) (AccountWebKey, bool, error) {
	var out AccountWebKey
	err := c.doJSON(ctx, http.MethodGet, "/v1/account/web-key", nil, &out)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
			return AccountWebKey{}, false, nil
		}
		return AccountWebKey{}, false, err
	}
	return out, true, nil
}

// ResealFormResponsesWeb attaches owner web-sealed content keys to existing responses so
// they become readable in the portal. Returns how many the server stored.
func (c *Client) ResealFormResponsesWeb(ctx context.Context, formID string, seals []ResponseWebSeal) (int, error) {
	in := struct {
		Seals []ResponseWebSeal `json:"seals"`
	}{Seals: seals}
	var out struct {
		Resealed int `json:"resealed"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/v1/forms/"+url.PathEscape(formID)+"/reseal-web", in, &out)
	return out.Resealed, err
}
