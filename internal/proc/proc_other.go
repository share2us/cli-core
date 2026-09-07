// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

//go:build !windows

package proc

import "os/exec"

// Nothing to do: only Windows allocates a console for a child process.
func hide(cmd *exec.Cmd) {}
