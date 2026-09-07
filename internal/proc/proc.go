// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

// Package proc holds the small platform differences in how a helper command is
// launched.
//
// It exists for one Windows behaviour: a GUI application has no console, so
// starting a console program allocates one, and a window flashes on screen. A
// desktop app that polls in the background would do that on every tick.
package proc

import "os/exec"

// Hidden builds a command that runs without flashing a console window on
// Windows. Every helper the desktop app runs in the background must be built
// this way; on other platforms it is exactly exec.Command.
func Hidden(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	hide(cmd)
	return cmd
}

// Hide applies the same treatment to a command built elsewhere.
func Hide(cmd *exec.Cmd) *exec.Cmd {
	hide(cmd)
	return cmd
}
