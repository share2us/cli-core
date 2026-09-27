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

func TestAgentClientRoundTrips(t *testing.T) {
	var lastPath, lastMethod, lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath, lastMethod = r.URL.String(), r.Method
		b := make([]byte, r.ContentLength)
		if r.ContentLength > 0 {
			_, _ = r.Body.Read(b)
			lastBody = string(b)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/agent/sessions":
			_, _ = w.Write([]byte(`{"sessions":[{"session_id":"s1","tool":"claude","device_name":"jarvis","status":"idle"}]}`))
		case r.Method == "POST" && r.URL.Path == "/v1/agent/inject":
			_, _ = w.Write([]byte(`{"id":"req-1","status":"pending","target_status":"idle","busy":false}`))
		case r.URL.Path == "/v1/agent/requests":
			_, _ = w.Write([]byte(`{"requests":[{"id":"req-1","tool":"claude","sealed_prompt":"BLOB","target_session_id":"s1","has_file":false}]}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "s2s_devtoken")

	if err := c.RegisterAgentSession(context.Background(), AgentRegisterInput{SessionID: "s1", Tool: "claude", Status: "busy"}); err != nil {
		t.Fatal(err)
	}
	if lastMethod != "POST" || lastPath != "/v1/agent/sessions" {
		t.Fatalf("register hit %s %s", lastMethod, lastPath)
	}
	var reg map[string]any
	_ = json.Unmarshal([]byte(lastBody), &reg)
	if reg["session_id"] != "s1" || reg["status"] != "busy" {
		t.Fatalf("register body = %s", lastBody)
	}

	sessions, err := c.ListAgentSessions(context.Background())
	if err != nil || len(sessions) != 1 || sessions[0].DeviceName != "jarvis" {
		t.Fatalf("list = %+v err=%v", sessions, err)
	}

	res, err := c.AgentInject(context.Background(), AgentInjectInput{TargetDeviceID: "d", TargetSessionID: "s1", Tool: "claude", SealedPrompt: "BLOB"})
	if err != nil || res.ID != "req-1" || res.Status != "pending" || res.TargetStatus != "idle" {
		t.Fatalf("inject = %+v err=%v", res, err)
	}

	reqs, err := c.AgentLongPoll(context.Background(), 1)
	if err != nil || len(reqs) != 1 || reqs[0].SealedPrompt != "BLOB" {
		t.Fatalf("longpoll = %+v err=%v", reqs, err)
	}
}

func TestListingsIncludingOfflineAskForThem(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/agent/sessions":
			_, _ = w.Write([]byte(`{"sessions":[{"session_id":"s1","status":"offline","last_seen":"2026-09-27T10:00:00Z"}]}`))
		default:
			_, _ = w.Write([]byte(`{"agents":[{"agent_id":"agt_x","session_id":"s2","status":"offline"}]}`))
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "s2s_devtoken")
	s, err := c.ListAgentSessionsIncludingOffline(context.Background())
	if err != nil || len(s) != 1 || s[0].Status != "offline" || s[0].LastSeen == "" {
		t.Fatalf("sessions: %+v, %v", s, err)
	}
	a, err := c.ListProjectAgentsIncludingOffline(context.Background(), "p 1")
	if err != nil || len(a) != 1 || a[0].Status != "offline" {
		t.Fatalf("agents: %+v, %v", a, err)
	}
	want := []string{"/v1/agent/sessions?include_offline=1", "/v1/agent/projects/p 1/agents?include_offline=1"}
	if len(queries) != 2 || queries[0] != want[0] || queries[1] != want[1] {
		t.Fatalf("requests %q, want %q", queries, want)
	}
}
