// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProjectAgentCalls(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/v1/agent/projects/p-1/agents":
			_ = json.NewEncoder(w).Encode(map[string]any{"agents": []map[string]any{{
				"agent_id": "agt_x", "session_id": "s1", "device_id": "d1", "device_public_key": "pk", "yours": true,
			}}})
		case "/v1/agent-invites":
			_ = json.NewEncoder(w).Encode(map[string]any{"agent_invites": []map[string]any{{
				"id": "inv-1", "agent_id": "agt_x", "pending": true, "project_name": "Checkout",
			}}})
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "s2s_devtoken")
	ctx := context.Background()

	agents, err := c.ListProjectAgents(ctx, "p-1")
	if err != nil || len(agents) != 1 || agents[0].DevicePublicKey != "pk" || !agents[0].Yours {
		t.Fatalf("ListProjectAgents = %+v, %v", agents, err)
	}
	invites, err := c.ListAgentInvites(ctx)
	if err != nil || len(invites) != 1 || !invites[0].Pending || invites[0].ProjectName != "Checkout" {
		t.Fatalf("ListAgentInvites = %+v, %v", invites, err)
	}
	if err := c.AcceptAgentInvite(ctx, "inv-1"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeclineAgentInvite(ctx, "inv-2"); err != nil {
		t.Fatal(err)
	}
	if err := c.WithdrawAgent(ctx, "p-1", "inv-1"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET /v1/agent/projects/p-1/agents", "GET /v1/agent-invites",
		"POST /v1/agent-invites/inv-1/accept", "POST /v1/agent-invites/inv-2/decline",
		"DELETE /v1/projects/p-1/agents/inv-1",
	}
	if len(seen) != len(want) {
		t.Fatalf("calls = %v", seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("call %d = %q, want %q", i, seen[i], want[i])
		}
	}
}

// The new fields are omitted when empty, so a same-account hop's body is
// unchanged for older servers.
func TestInjectInputOmitsEmptyProjectFields(t *testing.T) {
	raw, _ := json.Marshal(AgentInjectInput{TargetDeviceID: "d", TargetSessionID: "s", Tool: "claude", SealedPrompt: "x"})
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if _, ok := m["project_id"]; ok {
		t.Fatalf("empty project_id serialized: %s", raw)
	}
	if _, ok := m["sender_agent_id"]; ok {
		t.Fatalf("empty sender_agent_id serialized: %s", raw)
	}
}
