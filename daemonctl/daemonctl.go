// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package daemonctl

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	clicore "github.com/share2us/cli-core"
)

// ErrAlreadyRunning is returned by Listen when another daemon already holds the
// per-user control endpoint (the single-instance guard).
var ErrAlreadyRunning = errors.New("another share2us daemon is already running")

// Request is a control-channel message. Every request must carry the per-user
// token; a mismatch is rejected. Ops: "ping" (liveness), "status"
// (pid/version/uptime/what it owns), "stop" (self-cancel), "owns-receiver"
// (the cheap probe the GUI uses to decide whether to run its own receiver).
type Request struct {
	Token string `json:"token"`
	Op    string `json:"op"`
}

// Response is the reply to a Request.
type Response struct {
	OK        bool   `json:"ok"`
	PID       int    `json:"pid,omitempty"`
	Version   string `json:"version,omitempty"`
	OwnsLAN   bool   `json:"owns_lan,omitempty"`
	OwnsInbox bool   `json:"owns_inbox,omitempty"`
	Since     string `json:"since,omitempty"`
	Err       string `json:"err,omitempty"`
}

// dialTimeout bounds a control round-trip. The GUI's owns-receiver probe must be
// cheap and never hang the tray startup, so keep this short.
const dialTimeout = 400 * time.Millisecond

// LoadOrCreateToken returns the per-user control token, creating it (32 random
// bytes, hex, 0600) on first use. The token authenticates control requests so no
// other local user can drive this daemon.
func LoadOrCreateToken() (string, error) {
	path, err := clicore.DaemonTokenPath()
	if err != nil {
		return "", err
	}
	if b, err := os.ReadFile(path); err == nil {
		if tok := strings.TrimSpace(string(b)); tok != "" {
			return tok, nil
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(buf)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

// Listen binds the per-user control endpoint and serves control requests with
// handler until the returned Closer is closed. Binding the endpoint is the
// single-instance lock: if another live daemon holds it, Listen returns
// ErrAlreadyRunning. A stale socket left by a crashed daemon (nobody answering a
// ping) is removed and rebound.
func Listen(handler func(Request) Response) (io.Closer, error) {
	endpoint, err := controlEndpoint()
	if err != nil {
		return nil, err
	}
	tok, err := LoadOrCreateToken()
	if err != nil {
		return nil, err
	}
	// bindControl is the single-instance lock: it returns ErrAlreadyRunning when
	// another live daemon already holds this user's control endpoint, and clears a
	// stale one left by a crash. release frees the lock on Close.
	ln, release, err := bindControl(endpoint)
	if err != nil {
		return nil, err
	}
	srv := &controlServer{ln: ln, token: tok, handler: handler, release: release}
	go srv.serve()
	return srv, nil
}

type controlServer struct {
	ln      net.Listener
	token   string
	handler func(Request) Response
	release func()
}

func (s *controlServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handle(conn)
	}
}

func (s *controlServer) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		writeResp(conn, Response{Err: "bad request"})
		return
	}
	// Constant-time token compare; a mismatch reveals nothing and does nothing.
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.token)) != 1 {
		writeResp(conn, Response{Err: "unauthorized"})
		return
	}
	writeResp(conn, s.handler(req))
}

func (s *controlServer) Close() error {
	err := s.ln.Close()
	if s.release != nil {
		s.release()
	}
	return err
}

func writeResp(w io.Writer, r Response) {
	b, _ := json.Marshal(r)
	_, _ = w.Write(append(b, '\n'))
}

// dial sends one authenticated request and returns the response.
func dial(endpoint, token string, req Request) (Response, error) {
	req.Token = token
	conn, err := dialControl(endpoint, dialTimeout)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	b, _ := json.Marshal(req)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return Response{}, err
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return Response{}, err
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

// Query sends a control request to a running daemon, loading the token from disk.
// It returns (Response, true) when a daemon answered, or (_, false) when none is
// reachable. Used by `daemon status`/`stop` and the GUI handoff probe.
func Query(op string) (Response, bool) {
	endpoint, err := controlEndpoint()
	if err != nil {
		return Response{}, false
	}
	tok, err := LoadOrCreateToken()
	if err != nil {
		return Response{}, false
	}
	resp, err := dial(endpoint, tok, Request{Op: op})
	if err != nil {
		return Response{}, false
	}
	return resp, true
}

// Running reports whether a daemon currently answers on the control endpoint.
func Running() bool {
	resp, ok := Query("ping")
	return ok && resp.OK
}

// OwnsReceiver reports whether a running daemon is holding the account-inbox
// and/or LAN receiver, so a second process (the GUI tray) can defer to it
// instead of double-binding the LAN port or double-downloading the inbox.
func OwnsReceiver() bool {
	resp, ok := Query("owns-receiver")
	return ok && resp.OK
}
