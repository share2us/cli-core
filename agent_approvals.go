// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Owner approvals for agent actions the target's guard refused (ADR-052). The device that
// runs the agent files a request and polls it; the owner decides in the portal. Grants are
// what an approval leaves behind for one agent.

type ApprovalRequest struct {
	AgentID     string `json:"agent_id"`
	SessionID   string `json:"session_id,omitempty"`
	RequestID   string `json:"request_id,omitempty"`
	SenderLabel string `json:"sender_label,omitempty"`
	Tool        string `json:"tool"`
	// DisplayText is what the owner sees: the command with secrets hidden. The exact
	// command stays on the device; CommandHash identifies it.
	DisplayText string `json:"display_text"`
	CommandHash string `json:"command_hash"`
	Reason      string `json:"reason,omitempty"`
}

type ApprovalState struct {
	ID        string `json:"id"`
	Status    string `json:"status"` // pending | approved | denied | expired
	Scope     string `json:"scope,omitempty"`
	Minutes   int    `json:"minutes,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Consumed  bool   `json:"consumed"`
	Continued bool   `json:"continued"`
	// Note: what the owner wrote with the decision, for the agent (may be empty).
	Note string `json:"note,omitempty"`
}

type ActionGrant struct {
	ID          string     `json:"id"`
	AgentID     string     `json:"agent_id"`
	Scope       string     `json:"scope"` // command | all
	CommandHash string     `json:"command_hash,omitempty"`
	Pattern     string     `json:"pattern,omitempty"`
	DisplayText string     `json:"display_text,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// CreateApproval files a request (an identical pending one is returned instead).
func (c *Client) CreateApproval(ctx context.Context, in ApprovalRequest) (id, pageURL string, created bool, err error) {
	var out struct {
		ID      string `json:"id"`
		URL     string `json:"url"`
		Created bool   `json:"created"`
	}
	err = c.doJSON(ctx, http.MethodPost, "/v1/agent/approvals", in, &out)
	return out.ID, out.URL, out.Created, err
}

func (c *Client) GetApproval(ctx context.Context, id string) (ApprovalState, error) {
	var out ApprovalState
	err := c.doJSON(ctx, http.MethodGet, "/v1/agent/approvals/"+url.PathEscape(id), nil, &out)
	return out, err
}

// ConsumeApproval uses a once-approval (it can be used one time only).
func (c *Client) ConsumeApproval(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/agent/approvals/"+url.PathEscape(id)+"/consume", nil, nil)
}

// ContinueApproval reopens the finished hop of a late approval (once), so the agent's next
// result reaches the sender.
func (c *Client) ContinueApproval(ctx context.Context, id string) (requestID string, err error) {
	var out struct {
		RequestID string `json:"request_id"`
	}
	err = c.doJSON(ctx, http.MethodPost, "/v1/agent/approvals/"+url.PathEscape(id)+"/continue", nil, &out)
	return out.RequestID, err
}

func (c *Client) ListActionGrants(ctx context.Context) ([]ActionGrant, error) {
	var out struct {
		Grants []ActionGrant `json:"grants"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v1/agent/grants", nil, &out)
	return out.Grants, err
}

func (c *Client) RevokeActionGrant(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/agent/grants/"+url.PathEscape(id), nil, nil)
}
