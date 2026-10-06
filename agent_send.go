// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/share2us/cli-core/lanid"
)

// agentInjectEnvelope is the sender-side mirror of the daemon's InjectEnvelope.
// The JSON field names MUST stay identical to the receiver's or a delivered hop
// will not parse; kept here so the CLI and the desktop app share one send path.
// TestAgentInjectEnvelopeShape guards the field names.
type agentInjectEnvelope struct {
	Prompt               string `json:"prompt"`
	FileName             string `json:"file_name,omitempty"`
	Deliver              string `json:"deliver,omitempty"`
	SenderLANFingerprint string `json:"sender_lan_fingerprint,omitempty"`
	SenderDeviceName     string `json:"sender_device_name,omitempty"`
}

// SendAgentFileParams describes one agent inject: a prompt and/or a file, sealed
// to the target device and signed by this device's hop key.
type SendAgentFileParams struct {
	// Target, as the directory reports it.
	TargetDeviceID       string
	TargetSessionID      string
	Tool                 string
	TargetPublicKey      string // target device public key; the payload is sealed to it
	TargetLANFingerprint string // target's lanid fingerprint; "" forces the relay
	TargetAgentID        string

	// Payload.
	Prompt   string // may be empty when only a file is sent
	FilePath string // "" => prompt only
	Inbox    bool   // drop the file in the agent's inbox without running a prompt

	// Context.
	GoalID           string
	ProjectID        string
	SenderAgentID    string
	SenderDeviceName string // shown to the recipient
}

// SendAgentFileResult reports what the server accepted and which transport an
// attached file took.
type SendAgentFileResult struct {
	RequestID string
	Status    string // "queued" | "pending"
	Busy      bool
	Transport string // "direct LAN" | "relay" | "" when no file was sent
}

// SendAgentFile seals an agent inject (prompt and/or file) to the target device,
// signs the hop with this device's key (ADR-041 §5), and submits it. An attached
// file goes directly over LAN/Tailscale when the target's agent-file receiver is
// reachable, otherwise over the relay; the chosen transport is reported. The
// credential must already hold a registered device signing key (login does this);
// SendAgentFile does not register one.
func (c *Client) SendAgentFile(ctx context.Context, cred Credential, p SendAgentFileParams) (SendAgentFileResult, error) {
	if strings.TrimSpace(cred.DeviceSessionID) == "" {
		return SendAgentFileResult{}, errors.New("this login has no device session; sign in again to send signed hops")
	}
	if strings.TrimSpace(cred.DeviceSigningPrivateKey) == "" {
		return SendAgentFileResult{}, errors.New("this device has no hop signing key; sign in again")
	}
	if strings.TrimSpace(p.TargetPublicKey) == "" {
		return SendAgentFileResult{}, errors.New("target device public key is required to seal the inject")
	}

	env := agentInjectEnvelope{
		Prompt:               p.Prompt,
		SenderDeviceName:     p.SenderDeviceName,
		SenderLANFingerprint: lanid.Fingerprint(),
	}
	if p.Inbox {
		env.Deliver = "inbox"
	}

	// Nonce first: a direct LAN push stages its ciphertext keyed by this nonce
	// before the inject exists, and the hop is then signed with the same nonce.
	nonce, err := NewHopNonce()
	if err != nil {
		return SendAgentFileResult{}, err
	}

	var objectKey, sealedFileKey, transport string
	var lanFile bool
	if strings.TrimSpace(p.FilePath) != "" {
		data, rerr := os.ReadFile(p.FilePath)
		if rerr != nil {
			return SendAgentFileResult{}, rerr
		}
		ck, kerr := NewContentKey()
		if kerr != nil {
			return SendAgentFileResult{}, kerr
		}
		var enc bytes.Buffer
		if eerr := EncryptStream(&enc, bytes.NewReader(data), ck); eerr != nil {
			return SendAgentFileResult{}, eerr
		}
		// LAN/TUN first; fall back to the relay on any failure.
		if p.TargetLANFingerprint != "" && pushAgentFileLAN(ctx, p.TargetLANFingerprint, env.SenderDeviceName, nonce, enc.Bytes()) {
			lanFile, transport = true, "direct LAN"
		} else {
			objectKey, err = c.AgentUploadContent(ctx, enc.Bytes())
			if err != nil {
				return SendAgentFileResult{}, err
			}
			transport = "relay"
		}
		sealedFileKey, err = SealContentKeyForDevice(ck, p.TargetPublicKey)
		if err != nil {
			return SendAgentFileResult{}, err
		}
		env.FileName = filepath.Base(p.FilePath)
	}

	envBytes, _ := json.Marshal(env)
	sealed, err := SealForDevice(envBytes, p.TargetPublicKey)
	if err != nil {
		return SendAgentFileResult{}, err
	}

	in := AgentInjectInput{
		TargetDeviceID:  strings.TrimSpace(p.TargetDeviceID),
		TargetSessionID: strings.TrimSpace(p.TargetSessionID),
		Tool:            strings.ToLower(strings.TrimSpace(p.Tool)),
		SealedPrompt:    sealed,
		ObjectKey:       objectKey,
		LANFile:         lanFile,
		SealedFileKey:   sealedFileKey,
		GoalID:          strings.TrimSpace(p.GoalID),
		ProjectID:       strings.TrimSpace(p.ProjectID),
		SenderAgentID:   strings.TrimSpace(p.SenderAgentID),
		TargetAgentID:   strings.TrimSpace(p.TargetAgentID),
	}
	if serr := signHopWithNonce(&in, cred, time.Now(), nonce); serr != nil {
		return SendAgentFileResult{}, serr
	}
	res, err := c.AgentInject(ctx, in)
	if err != nil {
		return SendAgentFileResult{}, err
	}
	return SendAgentFileResult{RequestID: res.ID, Status: res.Status, Busy: res.Busy, Transport: transport}, nil
}

// signHopWithNonce signs an inject in place with a caller-supplied nonce, over the
// values exactly as the server normalizes them (trimmed ids, lowercase tool), so
// the signature covers what the server acts on.
func signHopWithNonce(in *AgentInjectInput, cred Credential, now time.Time, nonce string) error {
	in.TargetDeviceID = strings.TrimSpace(in.TargetDeviceID)
	in.TargetSessionID = strings.TrimSpace(in.TargetSessionID)
	in.Tool = strings.ToLower(strings.TrimSpace(in.Tool))
	in.SealedFileKey = strings.TrimSpace(in.SealedFileKey)
	in.GoalID = strings.TrimSpace(in.GoalID)
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	in.SenderAgentID = strings.TrimSpace(in.SenderAgentID)
	in.TargetAgentID = strings.TrimSpace(in.TargetAgentID)
	issued := now.UTC().Truncate(time.Second)

	sig, err := SignHop(HopClaims{
		SenderDeviceID:  cred.DeviceSessionID,
		TargetDeviceID:  in.TargetDeviceID,
		TargetSessionID: in.TargetSessionID,
		Tool:            in.Tool,
		SealedPrompt:    in.SealedPrompt,
		SealedFileKey:   in.SealedFileKey,
		GoalID:          in.GoalID,
		IssuedAt:        issued,
		Nonce:           nonce,
		ProjectID:       in.ProjectID,
		SenderAgentID:   in.SenderAgentID,
		TargetAgentID:   in.TargetAgentID,
	}, cred.DeviceSigningPrivateKey)
	if err != nil {
		return err
	}
	in.Signature = sig
	in.IssuedAt = issued.Format(time.RFC3339)
	in.Nonce = nonce
	return nil
}
