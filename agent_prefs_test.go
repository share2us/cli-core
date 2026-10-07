// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import "testing"

func TestAgentPrefSetAndPrune(t *testing.T) {
	var c Config

	// Setting a non-empty pref creates the map and stores it.
	c.SetAgentPref("agt_one", AgentPrefs{Alias: "  Build bot  ", Pinned: true})
	got := c.AgentPref("agt_one")
	if got.Alias != "Build bot" { // trimmed
		t.Errorf("alias = %q, want %q", got.Alias, "Build bot")
	}
	if !got.Pinned || got.Hidden {
		t.Errorf("flags = %+v, want pinned only", got)
	}

	// Clearing every field prunes the entry and empties the map back to nil.
	c.SetAgentPref("agt_one", AgentPrefs{})
	if _, ok := c.Agents["agt_one"]; ok {
		t.Error("empty pref was not pruned")
	}
	if c.Agents != nil {
		t.Errorf("map not reset to nil after last entry removed: %v", c.Agents)
	}

	// An alias of only spaces is empty, so it prunes too.
	c.SetAgentPref("agt_two", AgentPrefs{Alias: "   "})
	if len(c.Agents) != 0 {
		t.Errorf("whitespace-only alias was stored: %v", c.Agents)
	}

	// A blank id is ignored.
	c.SetAgentPref("  ", AgentPrefs{Pinned: true})
	if len(c.Agents) != 0 {
		t.Errorf("blank id stored: %v", c.Agents)
	}
}

func TestAgentDisplayName(t *testing.T) {
	var c Config
	if got := c.AgentDisplayName("agt_x", "claude-1"); got != "claude-1" {
		t.Errorf("no alias: got %q, want server name", got)
	}
	c.SetAgentPref("agt_x", AgentPrefs{Alias: "Reviewer"})
	if got := c.AgentDisplayName("agt_x", "claude-1"); got != "Reviewer" {
		t.Errorf("with alias: got %q, want %q", got, "Reviewer")
	}
}

func TestUpdateAgentPrefRoundTrip(t *testing.T) {
	dir := t.TempDir()
	// Isolate os.UserConfigDir on both linux (XDG_CONFIG_HOME) and macOS ($HOME).
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)

	// A hide, then a rename, then unhide: each loads/mutates/saves, and the last
	// read must reflect all surviving changes (shared path used by CLI and app).
	if err := UpdateAgentPref("agt_z", func(p *AgentPrefs) { p.Hidden = true }); err != nil {
		t.Fatalf("hide: %v", err)
	}
	if err := UpdateAgentPref("agt_z", func(p *AgentPrefs) { p.Alias = "QA" }); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := UpdateAgentPref("agt_z", func(p *AgentPrefs) { p.Hidden = false }); err != nil {
		t.Fatalf("unhide: %v", err)
	}

	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := config.AgentPref("agt_z")
	if got.Alias != "QA" || got.Hidden {
		t.Errorf("round-trip prefs = %+v, want alias QA, not hidden", got)
	}
}
