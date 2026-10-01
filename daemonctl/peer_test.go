// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package daemonctl

import (
	"encoding/json"
	"os"
	"testing"
)

func TestPeerPIDComesFromTransportNotRequest(t *testing.T) {
	profile := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", profile)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("APPDATA", profile)
	t.Setenv("LOCALAPPDATA", profile)
	var claimed Request
	if err := json.Unmarshal([]byte(`{"op":"test","peer_pid":987654321}`), &claimed); err != nil {
		t.Fatal(err)
	}
	if claimed.PeerPID != 0 {
		t.Fatal("JSON supplied a server-attested peer PID")
	}
	closer, err := Listen(func(req Request) Response {
		return Response{OK: true, PID: req.PeerPID}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	resp, ok := Call(Request{Op: "test", PeerPID: 987654321})
	if !ok || !resp.OK || resp.PID != os.Getpid() {
		t.Fatalf("peer PID = %d, ok=%v, response=%+v; want this process %d", resp.PID, ok, resp, os.Getpid())
	}
}
