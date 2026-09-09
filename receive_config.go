// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ReceiveConfig is where files sent to this device land, and whether they land
// there by themselves. It is the ONE place all three receivers read (§AG):
//
//   - `s2u receive` used to default to the CURRENT WORKING DIRECTORY, so files
//     ended up wherever the shell happened to be.
//   - the desktop tray hardcoded the Downloads folder.
//   - the daemon read `daemon.dest_dir`, which nothing else honoured.
//
// Three behaviours, one of them a bug, and no way to change any of them. Dir now
// supersedes DaemonConfig.DestDir, which is still read so an existing daemon
// install keeps working.
type ReceiveConfig struct {
	// Dir is where received files are saved. "" = the platform Downloads dir.
	Dir string `json:"dir,omitempty"`
	// Auto decides whether an arrival is written to Dir by itself.
	//
	// A POINTER because "not answered yet" is a real, distinct state: the default
	// is to ASK on the first arrival (owner, 2026-09-09), which a plain bool
	// cannot express — false would silently mean "no" and never prompt. nil means
	// unanswered.
	Auto *bool `json:"auto,omitempty"`
}

// ResolvedReceive is ReceiveConfig with the fallbacks applied.
type ResolvedReceive struct {
	Dir string
	// Auto is the effective setting; AutoAnswered says whether a human ever chose
	// it. A caller that can prompt should ask when AutoAnswered is false rather
	// than act on Auto's zero value.
	Auto         bool
	AutoAnswered bool
}

// ReceiveSettings resolves the receive settings with defaults applied.
//
// Precedence for the directory: an explicit argument (handled by the caller) >
// receive.dir > the legacy daemon.dest_dir > the Downloads folder. ~/Downloads
// stays the default deliberately (owner, 2026-09-09): it is what already ships,
// so nobody's files move and there is nothing to migrate.
func (c Config) ReceiveSettings() ResolvedReceive {
	r := ResolvedReceive{Dir: DownloadsDir()}
	dir := ""
	if c.Receive != nil {
		dir = strings.TrimSpace(c.Receive.Dir)
		if c.Receive.Auto != nil {
			r.Auto = *c.Receive.Auto
			r.AutoAnswered = true
		}
	}
	// Back-compat: an existing daemon install configured daemon.dest_dir, and
	// must keep receiving where it always did.
	if dir == "" && c.Daemon != nil {
		dir = strings.TrimSpace(c.Daemon.DestDir)
	}
	if dir != "" {
		r.Dir = expandHome(dir)
	}
	return r
}

// DownloadsDir resolves the user's Downloads folder: $XDG_DOWNLOAD_DIR when set
// (Linux), otherwise ~/Downloads, which also covers %USERPROFILE%\Downloads on
// Windows. Falls back to "." only when there is no home directory at all.
func DownloadsDir() string {
	if d := strings.TrimSpace(os.Getenv("XDG_DOWNLOAD_DIR")); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, "Downloads")
}

// SetReceiveDir stores the receive folder. An empty value clears it, restoring
// the Downloads default. The path is expanded and made absolute so a later
// reader is not at the mercy of the working directory that set it.
func SetReceiveDir(dir string) error {
	config, err := LoadConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir = strings.TrimSpace(dir)
	if config.Receive == nil {
		config.Receive = &ReceiveConfig{}
	}
	if dir == "" {
		config.Receive.Dir = ""
	} else {
		abs, err := filepath.Abs(expandHome(dir))
		if err != nil {
			return err
		}
		config.Receive.Dir = abs
	}
	// The legacy key would otherwise keep winning for the daemon.
	if config.Daemon != nil {
		config.Daemon.DestDir = ""
	}
	return SaveConfig(config)
}

// SetReceiveAuto records whether arrivals are saved automatically. This is also
// what ANSWERS the first-arrival question, so calling it with either value stops
// the prompt from coming back.
func SetReceiveAuto(auto bool) error {
	config, err := LoadConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if config.Receive == nil {
		config.Receive = &ReceiveConfig{}
	}
	config.Receive.Auto = &auto
	return SaveConfig(config)
}

// expandHome resolves a leading ~ so a hand-edited config or a shell that did
// not expand it still points where the user meant.
func expandHome(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") && !(runtime.GOOS == "windows" && strings.HasPrefix(path, `~\`)) {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, path[2:])
}
