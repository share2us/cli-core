// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import "testing"

func TestContentClassMdxIsForm(t *testing.T) {
	cases := map[string]string{
		"survey.mdx":        "form",
		"Survey.MDX":        "form",
		"notes.md":          "markdown",
		"readme.markdown":   "markdown",
		"data.json":         "json",
	}
	for name, want := range cases {
		if got := ContentClassForNameAndType(name, ""); got != want {
			t.Errorf("ContentClassForNameAndType(%q) = %q, want %q", name, got, want)
		}
	}
}
