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
