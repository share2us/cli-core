// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"os"
	"path/filepath"
	"testing"
)

// The default has to stay ~/Downloads: it is what already ships, so choosing it
// means nobody's files move and there is nothing to migrate (owner, 2026-09-09).
func TestReceiveSettingsDefaultsToDownloads(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DOWNLOAD_DIR", "")

	got := Config{}.ReceiveSettings()
	if want := filepath.Join(home, "Downloads"); got.Dir != want {
		t.Fatalf("dir = %q, want %q", got.Dir, want)
	}
}

// "Not answered yet" is a real state, distinct from "off": the default is to ASK
// on the first arrival, which a plain bool could not express -- false would
// silently mean no and the question would never be put.
func TestReceiveSettingsDistinguishesUnansweredFromOff(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if got := (Config{}).ReceiveSettings(); got.Auto || got.AutoAnswered {
		t.Fatalf("a fresh config must be unanswered: %+v", got)
	}

	off := false
	got := Config{Receive: &ReceiveConfig{Auto: &off}}.ReceiveSettings()
	if got.Auto {
		t.Fatal("auto should be off")
	}
	if !got.AutoAnswered {
		t.Fatal("an explicit off IS an answer, and must stop the prompt coming back")
	}
}

// An existing daemon install configured daemon.dest_dir and must keep receiving
// where it always has.
func TestReceiveSettingsFallsBackToLegacyDaemonDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	got := Config{Daemon: &DaemonConfig{DestDir: "/legacy/dir"}}.ReceiveSettings()
	if got.Dir != "/legacy/dir" {
		t.Fatalf("dir = %q, want the legacy daemon dir", got.Dir)
	}
}

func TestReceiveSettingsPrefersReceiveDirOverLegacy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	got := Config{
		Receive: &ReceiveConfig{Dir: "/new/dir"},
		Daemon:  &DaemonConfig{DestDir: "/legacy/dir"},
	}.ReceiveSettings()
	if got.Dir != "/new/dir" {
		t.Fatalf("dir = %q, want the shared receive dir to win", got.Dir)
	}
}

// The daemon reads the same resolved value as everything else. This covers the
// case that a nil Daemon section used to skip: a config with a receive dir and
// no daemon block is now the normal shape.
func TestDaemonSettingsUseTheSharedReceiveDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	got := Config{Receive: &ReceiveConfig{Dir: "/shared/dir"}}.DaemonSettings()
	if got.DestDir != "/shared/dir" {
		t.Fatalf("daemon dest = %q, want the shared receive dir even with no daemon section", got.DestDir)
	}
}

func TestSetReceiveDirExpandsHomeAndClearsLegacy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if err := SaveConfig(Config{Daemon: &DaemonConfig{DestDir: "/legacy/dir"}}); err != nil {
		t.Fatal(err)
	}
	if err := SetReceiveDir("~/inbox"); err != nil {
		t.Fatal(err)
	}

	config, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, "inbox"); config.Receive.Dir != want {
		t.Fatalf("stored dir = %q, want the expanded %q", config.Receive.Dir, want)
	}
	// Left in place, the legacy key would keep winning for the daemon and the
	// two would silently disagree.
	if config.Daemon != nil && config.Daemon.DestDir != "" {
		t.Fatalf("legacy daemon.dest_dir survived: %q", config.Daemon.DestDir)
	}
}

// An empty value restores the default rather than storing "".
func TestSetReceiveDirEmptyRestoresDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_DOWNLOAD_DIR", "")

	if err := SetReceiveDir("/somewhere"); err != nil {
		t.Fatal(err)
	}
	if err := SetReceiveDir(""); err != nil {
		t.Fatal(err)
	}
	config, _ := LoadConfig()
	if got := config.ReceiveSettings().Dir; got != filepath.Join(home, "Downloads") {
		t.Fatalf("dir = %q, want the Downloads default back", got)
	}
}

// Either answer stops the first-arrival prompt; that is the point of recording it.
func TestSetReceiveAutoRecordsBothAnswers(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	for _, want := range []bool{true, false} {
		if err := SetReceiveAuto(want); err != nil {
			t.Fatal(err)
		}
		config, _ := LoadConfig()
		got := config.ReceiveSettings()
		if got.Auto != want || !got.AutoAnswered {
			t.Fatalf("auto=%v answered=%v, want auto=%v answered=true", got.Auto, got.AutoAnswered, want)
		}
	}
}

func TestDownloadsDirHonoursXDG(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := filepath.Join(os.TempDir(), "xdg-downloads")
	t.Setenv("XDG_DOWNLOAD_DIR", dir)

	if got := DownloadsDir(); got != dir {
		t.Fatalf("DownloadsDir = %q, want %q", got, dir)
	}
}
