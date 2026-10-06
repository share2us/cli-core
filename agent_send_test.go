// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"encoding/json"
	"testing"
)

// TestAgentInjectEnvelopeShape pins the wire field names. They MUST match the
// receiver's daemon.InjectEnvelope exactly, or a delivered hop fails to parse.
// If the receiver's JSON tags change, change them here too.
func TestAgentInjectEnvelopeShape(t *testing.T) {
	b, err := json.Marshal(agentInjectEnvelope{
		Prompt:               "p",
		FileName:             "f",
		Deliver:              "inbox",
		SenderLANFingerprint: "lan",
		SenderDeviceName:     "dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	want := []string{"prompt", "file_name", "deliver", "sender_lan_fingerprint", "sender_device_name"}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Errorf("envelope missing %q (must match daemon.InjectEnvelope): %s", k, b)
		}
	}
	if len(m) != len(want) {
		t.Errorf("envelope has %d keys, want %d: %s", len(m), len(want), b)
	}

	// omitempty: a prompt-only envelope carries just "prompt".
	b2, _ := json.Marshal(agentInjectEnvelope{Prompt: "only"})
	var m2 map[string]any
	_ = json.Unmarshal(b2, &m2)
	if len(m2) != 1 {
		t.Errorf("prompt-only envelope should have 1 key, got %s", b2)
	}
}
