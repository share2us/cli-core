// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"os"
	"strings"
)

// AgentPrefs are per-agent local presentation preferences, keyed by the stable
// AgentID (agt_...) in Config.Agents. They are local to this machine and shared
// by the CLI and the desktop app (both read the same config.json), so a pin,
// hide or rename made in one is seen by the other. They never leave the device
// and never change what anyone else sees: Alias is a display-name override only.
// An entry that carries no alias and neither flag is pruned so config.json stays
// clean.
type AgentPrefs struct {
	// Alias replaces the server-supplied agent name wherever this account shows
	// the agent, for this user only.
	Alias string `json:"alias,omitempty"`
	// Pinned sorts the agent to the top of agent lists.
	Pinned bool `json:"pinned,omitempty"`
	// Hidden removes the agent from the default listing (still reachable by id,
	// and shown when hidden agents are explicitly included).
	Hidden bool `json:"hidden,omitempty"`
}

func (p AgentPrefs) isEmpty() bool {
	return strings.TrimSpace(p.Alias) == "" && !p.Pinned && !p.Hidden
}

// AgentPref returns the stored prefs for an agent, or the zero value when none
// are stored.
func (c Config) AgentPref(agentID string) AgentPrefs {
	return c.Agents[strings.TrimSpace(agentID)]
}

// SetAgentPref stores prefs for an agent in the config, pruning the entry (and
// the whole map when it empties) if the prefs carry nothing.
func (c *Config) SetAgentPref(agentID string, p AgentPrefs) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return
	}
	p.Alias = strings.TrimSpace(p.Alias)
	if p.isEmpty() {
		delete(c.Agents, agentID)
		if len(c.Agents) == 0 {
			c.Agents = nil
		}
		return
	}
	if c.Agents == nil {
		c.Agents = map[string]AgentPrefs{}
	}
	c.Agents[agentID] = p
}

// AgentDisplayName returns the alias if one is set for the agent, else the
// server-supplied name. serverName is returned unchanged when there is no alias.
func (c Config) AgentDisplayName(agentID, serverName string) string {
	if alias := strings.TrimSpace(c.AgentPref(agentID).Alias); alias != "" {
		return alias
	}
	return serverName
}

// UpdateAgentPref loads the config, applies mut to the agent's prefs, and saves.
// This is the single mutation path the CLI and the desktop app both call, so a
// pin, hide or rename from one surface is immediately visible to the other.
func UpdateAgentPref(agentID string, mut func(*AgentPrefs)) error {
	config, err := LoadConfig()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	p := config.AgentPref(agentID)
	mut(&p)
	config.SetAgentPref(agentID, p)
	return SaveConfig(config)
}
