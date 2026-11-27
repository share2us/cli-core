package clicore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAgentDM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sharenets/net-1/dms" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["agent_id"] != "agt_x" || in["project_id"] != "proj-1" || in["username"] != "amna" {
			t.Errorf("body = %v", in)
		}
		_, _ = w.Write([]byte(`{"id":"dm-1","channel":"dm:dm-1","created":true}`))
	}))
	defer srv.Close()
	dm, err := NewClient(srv.URL, "s2s_test").OpenAgentDM(context.Background(), "net-1", "agt_x", "proj-1", "@amna")
	if err != nil || dm.Channel != "dm:dm-1" || !dm.Created {
		t.Fatalf("dm = %+v, %v", dm, err)
	}
}
