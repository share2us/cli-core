package clicore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Agent-session bridge client (ADR-036). These wrap the /v1/agent/* endpoints the
// daemon uses to register its live coding-agent sessions, receive relayed inject
// requests, and report results — and that a sender uses to inject.

// AgentSessionInfo is a session in the reachable directory.
type AgentSessionInfo struct {
	SessionID       string `json:"session_id"`
	Tool            string `json:"tool"`
	Name            string `json:"name"`
	Project         string `json:"project"`
	Status          string `json:"status"`
	DeviceID        string `json:"device_id"`
	DeviceName      string `json:"device_name"`
	DevicePublicKey string `json:"device_public_key"`
	LastSeen        string `json:"last_seen"`
}

// AgentRegisterInput registers/heartbeats one live session.
type AgentRegisterInput struct {
	SessionID string `json:"session_id"`
	Tool      string `json:"tool"`
	Name      string `json:"name"`
	Project   string `json:"project"`
	Status    string `json:"status"`
}

// AgentInjectInput submits a file+prompt for a target session. SealedPrompt (and
// SealedFileKey) are sealed to the target device's key by the caller (E2E).
type AgentInjectInput struct {
	TargetDeviceID  string `json:"target_device_id"`
	TargetSessionID string `json:"target_session_id"`
	Tool            string `json:"tool"`
	SealedPrompt    string `json:"sealed_prompt"`
	ObjectKey       string `json:"object_key,omitempty"`
	SealedFileKey   string `json:"sealed_file_key,omitempty"`
}

// AgentInjectResult is the server's response to an inject.
type AgentInjectResult struct {
	ID           string `json:"id"`
	Status       string `json:"status"` // "queued" or "pending"
	TargetStatus string `json:"target_status"`
	Busy         bool   `json:"busy"`
}

// AgentRequest is a relayed inject request delivered to (or pending on) a target
// device. The target decrypts SealedPrompt locally with its device key.
type AgentRequest struct {
	ID              string `json:"id"`
	SenderDeviceID  string `json:"sender_device_id"`
	TargetSessionID string `json:"target_session_id"`
	Tool            string `json:"tool"`
	SealedPrompt    string `json:"sealed_prompt"`
	// HasFile reports whether a file rides with this request. The storage key is
	// deliberately NOT exposed — download by request id with AgentDownloadContent.
	HasFile       bool   `json:"has_file"`
	SealedFileKey string `json:"sealed_file_key"`
	CreatedAt     string `json:"created_at"`
}

// AgentInjectState is a sender's view of a request's progress.
type AgentInjectState struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Result string `json:"result"`
}

// RegisterAgentSession advertises (or heartbeats) a live session.
func (c *Client) RegisterAgentSession(ctx context.Context, in AgentRegisterInput) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/agent/sessions", in, nil)
}

// ListAgentSessions returns the reachable session directory.
func (c *Client) ListAgentSessions(ctx context.Context) ([]AgentSessionInfo, error) {
	var out struct {
		Sessions []AgentSessionInfo `json:"sessions"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v1/agent/sessions", nil, &out)
	return out.Sessions, err
}

// DeregisterAgentSession removes a session the daemon no longer advertises.
func (c *Client) DeregisterAgentSession(ctx context.Context, sessionID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/agent/sessions?session_id="+url.QueryEscape(sessionID), nil, nil)
}

// AgentInject submits a file+prompt for a target session.
func (c *Client) AgentInject(ctx context.Context, in AgentInjectInput) (AgentInjectResult, error) {
	var out AgentInjectResult
	err := c.doJSON(ctx, http.MethodPost, "/v1/agent/inject", in, &out)
	return out, err
}

// AgentInjectStatus reads a request's status/result (sender side).
func (c *Client) AgentInjectStatus(ctx context.Context, id string) (AgentInjectState, error) {
	var out AgentInjectState
	err := c.doJSON(ctx, http.MethodGet, "/v1/agent/inject/"+url.PathEscape(id), nil, &out)
	return out, err
}

// AgentLongPoll holds a request open up to waitSeconds and returns any queued
// requests for this device (target side). The caller should pass a context whose
// deadline exceeds waitSeconds.
func (c *Client) AgentLongPoll(ctx context.Context, waitSeconds int) ([]AgentRequest, error) {
	if waitSeconds <= 0 || waitSeconds > 30 {
		waitSeconds = 25
	}
	var out struct {
		Requests []AgentRequest `json:"requests"`
	}
	err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/v1/agent/requests?wait=%d", waitSeconds), nil, &out)
	return out.Requests, err
}

// AgentPending lists inject requests awaiting this device's approval (target side).
func (c *Client) AgentPending(ctx context.Context) ([]AgentRequest, error) {
	var out struct {
		Requests []AgentRequest `json:"requests"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v1/agent/pending", nil, &out)
	return out.Requests, err
}

// AgentAllow auto-allows a sender device to inject into this device (target side).
func (c *Client) AgentAllow(ctx context.Context, senderDeviceID string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/agent/allow", map[string]string{"sender_device_id": senderDeviceID}, nil)
}

// AgentReportResult reports a request's progress/outcome (target side).
func (c *Client) AgentReportResult(ctx context.Context, id, status, result string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/agent/inject/"+url.PathEscape(id)+"/result",
		map[string]string{"status": status, "result": result}, nil)
}

// AgentUploadContent uploads a ciphertext blob (an encrypted file for an inject)
// and returns its object key, to pass as AgentInjectInput.ObjectKey.
func (c *Client) AgentUploadContent(ctx context.Context, ciphertext []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/agent/upload", bytes.NewReader(ciphertext))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := readLimitedBody(resp)
		if apiErr := decodeAPIErrorFromBody(resp, body); apiErr.Code != "" {
			return "", apiErr
		}
		return "", &APIError{Status: resp.StatusCode, Code: "upload_failed", Message: fmt.Sprintf("agent upload failed: HTTP %d", resp.StatusCode)}
	}
	var out struct {
		ObjectKey string `json:"object_key"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJSONResponse)).Decode(&out); err != nil {
		return "", err
	}
	return out.ObjectKey, nil
}

// AgentDownloadContent streams the ciphertext for a delivered inject request to
// dst (target side); decrypt it with the content key opened from SealedFileKey.
func (c *Client) AgentDownloadContent(ctx context.Context, id string, dst io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/agent/inject/"+url.PathEscape(id)+"/content", nil)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := readLimitedBody(resp)
		if apiErr := decodeAPIErrorFromBody(resp, body); apiErr.Code != "" {
			return apiErr
		}
		return &APIError{Status: resp.StatusCode, Code: "download_failed", Message: fmt.Sprintf("agent content failed: HTTP %d", resp.StatusCode)}
	}
	_, err = io.Copy(dst, resp.Body)
	return err
}

// AgentGrant is a standing allow held by this device.
type AgentGrant struct {
	SenderDeviceID string `json:"sender_device_id"`
	ApprovedAt     string `json:"approved_at"`
}

// AgentApproveOnce approves a single pending request WITHOUT granting the sender
// standing access (target side).
func (c *Client) AgentApproveOnce(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/agent/inject/"+url.PathEscape(id)+"/approve", nil, nil)
}

// AgentRevoke withdraws a sender device's standing access to this device.
func (c *Client) AgentRevoke(ctx context.Context, senderDeviceID string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/agent/revoke", map[string]string{"sender_device_id": senderDeviceID}, nil)
}

// AgentAllowed lists the sender devices this device currently grants standing
// access to.
func (c *Client) AgentAllowed(ctx context.Context) ([]AgentGrant, error) {
	var out struct {
		Grants []AgentGrant `json:"grants"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v1/agent/allowed", nil, &out)
	return out.Grants, err
}
