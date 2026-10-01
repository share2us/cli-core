// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

//go:build !windows

package daemonctl

import (
	"os"
	"testing"
)

// macOS rejects Unix socket paths longer than 104 bytes. Go's t.TempDir under
// /var/folders can already use most of that budget before daemon.sock is added.
func shortRuntimeDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "s2u-ctl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
