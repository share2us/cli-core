// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"os"
	"path/filepath"
	"testing"
)

// §AJ #24: a sender-chosen file name written straight to disk replaced whatever
// was already there.
func TestUniquePathNeverReturnsAnExistingPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "notes.txt")
	if got := UniquePath(target); got != target {
		t.Fatalf("a free path was renamed: %q", got)
	}

	if err := os.WriteFile(target, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	first := UniquePath(target)
	if first == target {
		t.Fatal("an existing file would have been overwritten")
	}
	if filepath.Base(first) != "notes (1).txt" {
		t.Fatalf("first alternative = %q", filepath.Base(first))
	}
	if err := os.WriteFile(first, []byte("also mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if second := UniquePath(target); second != filepath.Join(dir, "notes (2).txt") {
		t.Fatalf("second alternative = %q", second)
	}
	// The original is untouched throughout.
	if body, _ := os.ReadFile(target); string(body) != "mine" {
		t.Fatalf("the original file changed: %q", body)
	}
}

// A dangling symlink is still "something that exists": following it would write
// through to wherever it points.
func TestUniquePathTreatsASymlinkAsOccupied(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), target); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if got := UniquePath(target); got == target {
		t.Fatal("a symlink was treated as a free path; the write would follow it")
	}
}

// Names with no extension, and names that are all extension, still work.
func TestUniquePathEdgeNames(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"Makefile", ".bashrc", "archive.tar.gz"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		got := UniquePath(p)
		if got == p {
			t.Fatalf("%s would have been overwritten", name)
		}
		if _, err := os.Lstat(got); !os.IsNotExist(err) {
			t.Fatalf("%s -> %s which already exists", name, got)
		}
	}
}
