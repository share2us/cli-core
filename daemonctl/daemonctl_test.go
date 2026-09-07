// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

//go:build !windows

package daemonctl

import (
	"os"
	"path/filepath"
	"testing"

	clicore "github.com/share2us/cli-core"
)

func perUserDirs(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
}

func okHandler(req Request) Response {
	switch req.Op {
	case "ping":
		return Response{OK: true}
	case "owns-receiver":
		return Response{OK: true, OwnsInbox: true}
	default:
		return Response{Err: "unknown op"}
	}
}

func TestListenSingleInstanceAndProbe(t *testing.T) {
	perUserDirs(t)
	closer, err := Listen(okHandler)
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	defer closer.Close()

	if _, err := Listen(okHandler); err != ErrAlreadyRunning {
		t.Fatalf("second Listen = %v, want ErrAlreadyRunning", err)
	}
	if !Running() {
		t.Fatal("Running() = false while a daemon holds the socket")
	}
	if !OwnsReceiver() {
		t.Fatal("OwnsReceiver() = false while the handler reports it owns the inbox")
	}
}

func TestListenClearsStaleSocket(t *testing.T) {
	perUserDirs(t)
	sock, err := clicore.DaemonSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sock, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	closer, err := Listen(okHandler)
	if err != nil {
		t.Fatalf("Listen over stale socket: %v", err)
	}
	closer.Close()
}

func TestRejectsBadToken(t *testing.T) {
	perUserDirs(t)
	closer, err := Listen(okHandler)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	sock, _ := clicore.DaemonSocketPath()
	resp, err := dial(sock, "wrong", Request{Op: "ping"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if resp.OK || resp.Err != "unauthorized" {
		t.Fatalf("bad-token response = %+v, want unauthorized", resp)
	}
}

func TestQueryNoDaemon(t *testing.T) {
	perUserDirs(t)
	if _, ok := Query("status"); ok {
		t.Fatal("Query ok with no daemon")
	}
	if Running() || OwnsReceiver() {
		t.Fatal("Running/OwnsReceiver true with no daemon")
	}
}
