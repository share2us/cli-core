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
