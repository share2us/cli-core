// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package daemonctl

import (
	"encoding/json"
	"os"
	"runtime"
	"testing"
)

func TestPeerPIDComesFromTransportNotRequest(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Setenv("XDG_RUNTIME_DIR", shortRuntimeDir(t))
	}
	var claimed Request
	if err := json.Unmarshal([]byte(`{"op":"test","peer_pid":987654321}`), &claimed); err != nil {
		t.Fatal(err)
	}
	if claimed.PeerPID != 0 {
		t.Fatal("JSON supplied a server-attested peer PID")
	}
	endpoint, err := controlEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	ln, release, err := bindControl(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	srv := &controlServer{ln: ln, release: release, token: "test", handler: func(req Request) Response {
		return Response{OK: true, PID: req.PeerPID}
	}}
	go srv.serve()
	defer srv.Close()
	resp, err := dial(endpoint, "test", Request{Op: "test", PeerPID: 987654321})
	if err != nil || !resp.OK || resp.PID != os.Getpid() {
		t.Fatalf("peer PID = %d, error=%v, response=%+v; want this process %d", resp.PID, err, resp, os.Getpid())
	}
}
