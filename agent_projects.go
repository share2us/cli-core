// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"context"
	"net/http"
	"net/url"
)

// Agents working across accounts inside a sharenet project (ADR-041 §2a).
//
// A host invites a specific agent into a project; the agent's owner accepts;
// from then on the project's member agents can reach each other, and nothing
// else of each other's accounts.

// ProjectAgentAddress is where a project's member agent can be reached: the
// session to target and the device key to seal the prompt to.
type ProjectAgentAddress struct {
	AgentID         string `json:"agent_id"`
	Function        string `json:"function"`
	SessionID       string `json:"session_id"`
	Tool            string `json:"tool"`
	Status          string `json:"status"`
	DeviceID        string `json:"device_id"`
	DevicePublicKey string `json:"device_public_key"`
	LastSeen        string `json:"last_seen"`
	// Yours marks this account's own agents.
	Yours bool `json:"yours"`
}

// ListProjectAgents returns the reachable member agents of a project. Only a
// device that runs a member agent of the project may ask.
func (c *Client) ListProjectAgents(ctx context.Context, projectID string) ([]ProjectAgentAddress, error) {
	var out struct {
		Agents []ProjectAgentAddress `json:"agents"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v1/agent/projects/"+url.PathEscape(projectID)+"/agents", nil, &out)
	return out.Agents, err
}

// AgentInvite is an invitation for one of this account's agents to join a
// project, or (Pending false) a membership it already holds.
type AgentInvite struct {
	ID           string `json:"id"`
	AgentID      string `json:"agent_id"`
	Function     string `json:"function"`
	Pending      bool   `json:"pending"`
	InvitedAt    string `json:"invited_at"`
	AcceptedAt   string `json:"accepted_at,omitempty"`
	ProjectID    string `json:"project_id"`
	ProjectName  string `json:"project_name"`
	SharenetID   string `json:"sharenet_id"`
	SharenetName string `json:"sharenet_name"`
}

// ListAgentInvites returns invitations addressed to the signed-in account's
// email and the memberships its agents already hold.
func (c *Client) ListAgentInvites(ctx context.Context) ([]AgentInvite, error) {
	var out struct {
		Invites []AgentInvite `json:"agent_invites"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v1/agent-invites", nil, &out)
	return out.Invites, err
}

// AcceptAgentInvite admits the invited agent into the project.
func (c *Client) AcceptAgentInvite(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/agent-invites/"+url.PathEscape(id)+"/accept", nil, nil)
}

// DeclineAgentInvite refuses the invitation.
func (c *Client) DeclineAgentInvite(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/agent-invites/"+url.PathEscape(id)+"/decline", nil, nil)
}

// WithdrawAgent removes one of this account's agents from a project it joined.
// membershipID is the invitation's id.
func (c *Client) WithdrawAgent(ctx context.Context, projectID, membershipID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/projects/"+url.PathEscape(projectID)+"/agents/"+url.PathEscape(membershipID), nil, nil)
}
