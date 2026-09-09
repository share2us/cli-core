// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// UniquePath returns p, or the first "name (n).ext" variant that does not exist.
//
// It is for names the LOCAL USER did not choose: a file name that came from a
// sender, or from a gateway's Content-Disposition. Writing those straight to
// disk let a sender pick the name and silently replace whatever was already
// there -- .bashrc, Makefile, a document being edited -- with no prompt and no
// way back (§AJ #24). A name the user typed themselves is their own choice and
// is not routed through here.
func UniquePath(p string) string {
	if _, err := os.Lstat(p); os.IsNotExist(err) {
		return p
	}
	dir, name := filepath.Split(p)
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; i < 10000; i++ {
		cand := filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
		if _, err := os.Lstat(cand); os.IsNotExist(err) {
			return cand
		}
	}
	return p
}
