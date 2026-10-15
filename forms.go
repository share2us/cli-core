// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Interactive form shares (ADR-046). As of the 2026-10-15 reversal, responses are stored
// and read as PLAINTEXT (no E2E sealing, no web-key passphrase): the owner (and a
// submitter) list and fetch responses and read the answers directly.

// FormResponseMeta is one row in the owner's Submissions list. SubmitterEmail is revealed
// to the owner by design (a form is the owner's own form).
type FormResponseMeta struct {
	ID             string    `json:"id"`
	SubmitterEmail string    `json:"submitter_email"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
}

// FormResponsePayload is a submitted response: the plaintext answers plus metadata.
type FormResponsePayload struct {
	Answers        json.RawMessage `json:"answers"`
	SubmitterEmail string          `json:"submitter_email"`
	Status         string          `json:"status"`
	CreatedAt      time.Time       `json:"created_at"`
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

// GetFormResponse fetches one response the caller is allowed to read (owner or submitter).
func (c *Client) GetFormResponse(ctx context.Context, formID, responseID string) (FormResponsePayload, error) {
	var out FormResponsePayload
	path := "/v1/forms/" + url.PathEscape(formID) + "/responses/" + url.PathEscape(responseID)
	err := c.doJSON(ctx, http.MethodGet, path, nil, &out)
	return out, err
}
