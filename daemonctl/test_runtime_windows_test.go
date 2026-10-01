// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

//go:build windows

package daemonctl

import "testing"

func shortRuntimeDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
