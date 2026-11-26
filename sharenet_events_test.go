// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSharenetEventCalls(t *testing.T) {
	var query, readBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sharenets/n-1/events":
			query = r.URL.RawQuery
			_ = json.NewEncoder(w).Encode(map[string]any{
				"events": []map[string]any{{"id": 7, "channel": "p-1", "kind": "task", "actor_name": "Alice", "actor_agent": "reviewer",
					"created_at": "2026-11-26T10:00:00Z", "task": map[string]any{"status": "done", "target": "qa", "reply": "ok"}}},
				"unread": map[string]int{"general": 2},
			})
		case "/v1/sharenets/n-1/events/read":
			b, _ := io.ReadAll(r.Body)
			readBody = string(b)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "s2s_devtoken")
	evs, unread, err := c.ListSharenetEvents(context.Background(), "n-1", SharenetEventsQuery{Channel: "p-1", After: 5, Limit: 20})
	if err != nil || len(evs) != 1 || evs[0].Task == nil || evs[0].Task.Reply != "ok" || unread["general"] != 2 {
		t.Fatalf("events = %+v %v %v", evs, unread, err)
	}
	if query != "after=5&channel=p-1&limit=20" {
		t.Fatalf("query = %q", query)
	}
	if err := c.MarkSharenetRead(context.Background(), "n-1", "p-1", 7); err != nil || readBody != `{"channel":"p-1","last_event_id":7}` {
		t.Fatalf("read = %q %v", readBody, err)
	}
}

func TestMessageSealIsBoundToItsChannel(t *testing.T) {
	ek := make([]byte, 32)
	ct, err := SealSym(ek, []byte("deploy at 5"), MessageAAD("n-1", 3, "mid-0000000000000", "p-1"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := OpenSym(ek, ct, MessageAAD("n-1", 3, "mid-0000000000000", "p-1")); err != nil || string(pt) != "deploy at 5" {
		t.Fatalf("open = %q %v", pt, err)
	}
	if _, err := OpenSym(ek, ct, MessageAAD("n-1", 3, "mid-0000000000000", "general")); err == nil {
		t.Fatal("a message moved to another channel still opened")
	}
}

func TestPostSharenetMessage(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 42})
	}))
	defer srv.Close()
	id, err := NewClient(srv.URL, "s2s_x").PostSharenetMessage(context.Background(), "n-1", SharenetMessage{Channel: "p-1", Body: "hi", AgentID: "agt_x"})
	if err != nil || id != 42 || got["body"] != "hi" || got["agent_id"] != "agt_x" {
		t.Fatalf("post = %d %v %v", id, got, err)
	}
}
