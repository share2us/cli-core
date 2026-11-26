// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"context"
	"net/http"
	"net/url"
)

// Sharenet management from a signed-in device (owner, 2026-11-26: the CLI manages
// sharenets as well as the portal). The server applies the same role checks as for the
// portal and refuses personal API tokens. Deleting a sharenet and handing over ownership
// stay in the portal.

type SharenetMember struct {
	ID            string   `json:"id"`
	Role          string   `json:"role"`
	Pending       bool     `json:"pending"`
	You           bool     `json:"you"`
	Username      string   `json:"username,omitempty"`
	Name          string   `json:"display_name"`
	Email         string   `json:"email,omitempty"`
	AgentProjects []string `json:"agent_projects,omitempty"`
}

type SharenetDetail struct {
	SharenetSummary
	Members         []SharenetMember `json:"members"`
	MyAgentProjects []string         `json:"my_agent_projects"`
}

type JoinRequest struct {
	ID          string `json:"id"`
	AgentID     string `json:"agent_id"`
	AgentName   string `json:"agent_name"`
	Tool        string `json:"tool"`
	Function    string `json:"function"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	RequestedAt string `json:"requested_at"`
	ExpiresAt   string `json:"expires_at"`
}

type AddedAgent struct {
	AgentID  string `json:"agent_id"`
	ID       string `json:"id,omitempty"`
	Admitted bool   `json:"admitted"`
	CanPost  bool   `json:"can_post"`
	Error    string `json:"error,omitempty"`
}

func (c *Client) CreateSharenet(ctx context.Context, name string, secure bool) (SharenetSummary, error) {
	var out SharenetSummary
	err := c.doJSON(ctx, http.MethodPost, "/v1/sharenets", map[string]any{"name": name, "secure": secure}, &out)
	return out, err
}

func (c *Client) GetSharenet(ctx context.Context, sharenetID string) (SharenetDetail, error) {
	var out SharenetDetail
	err := c.doJSON(ctx, http.MethodGet, "/v1/sharenets/"+url.PathEscape(sharenetID), nil, &out)
	return out, err
}

// InviteToSharenet invites one email address. agentProjects is the "bring your agents"
// grant: projects the invitee may add their own agents to.
func (c *Client) InviteToSharenet(ctx context.Context, sharenetID, email, role string, agentProjects []string) (inviteID string, err error) {
	var out struct {
		ID string `json:"id"`
	}
	body := map[string]any{"email": email, "role": role, "agent_projects": agentProjects}
	err = c.doJSON(ctx, http.MethodPost, "/v1/sharenets/"+url.PathEscape(sharenetID)+"/invites", body, &out)
	return out.ID, err
}

func (c *Client) RemoveSharenetMember(ctx context.Context, sharenetID, memberID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/sharenets/"+url.PathEscape(sharenetID)+"/members/"+url.PathEscape(memberID), nil, nil)
}

func (c *Client) CreateSharenetProject(ctx context.Context, sharenetID, name string) (SharenetProject, error) {
	var out SharenetProject
	err := c.doJSON(ctx, http.MethodPost, "/v1/sharenets/"+url.PathEscape(sharenetID)+"/projects", map[string]any{"name": name}, &out)
	return out, err
}

// CreateJoinCode makes a code an agent's session redeems with `s2u agent join`. maxUses
// and expiresHours are optional (0 = the server's default: one use, 24 hours).
func (c *Client) CreateJoinCode(ctx context.Context, projectID, function string, maxUses, expiresHours int) (code, expiresAt string, err error) {
	var out struct {
		Code      string `json:"code"`
		ExpiresAt string `json:"expires_at"`
	}
	body := map[string]any{"function": function}
	if maxUses > 0 {
		body["max_uses"] = maxUses
	}
	if expiresHours > 0 {
		body["expires_in_hours"] = expiresHours
	}
	err = c.doJSON(ctx, http.MethodPost, "/v1/projects/"+url.PathEscape(projectID)+"/join-codes", body, &out)
	return out.Code, out.ExpiresAt, err
}

func (c *Client) ListJoinRequests(ctx context.Context, projectID string) ([]JoinRequest, error) {
	var out struct {
		Requests []JoinRequest `json:"requests"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v1/projects/"+url.PathEscape(projectID)+"/join-requests", nil, &out)
	return out.Requests, err
}

func (c *Client) DecideJoinRequest(ctx context.Context, projectID, requestID string, approve bool) error {
	verb := "reject"
	if approve {
		verb = "approve"
	}
	return c.doJSON(ctx, http.MethodPost, "/v1/projects/"+url.PathEscape(projectID)+"/join-requests/"+url.PathEscape(requestID)+"/"+verb, nil, nil)
}

// AddMyAgents adds several of the caller's own agents to a project, admitted at once;
// canPost lets them post files (only an agent's owner may grant that).
func (c *Client) AddMyAgents(ctx context.Context, projectID string, agentIDs []string, function string, canPost bool) ([]AddedAgent, error) {
	var out struct {
		Agents []AddedAgent `json:"agents"`
	}
	body := map[string]any{"agent_ids": agentIDs, "function": function, "can_post": canPost}
	err := c.doJSON(ctx, http.MethodPost, "/v1/projects/"+url.PathEscape(projectID)+"/agents/mine", body, &out)
	return out.Agents, err
}
