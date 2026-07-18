package p2p

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/coder/websocket"
)

// sigMsg is the relay wire message. It matches the share2us-relay protocol:
// JSON text frames {"type", "code"?, "sdp"?, "candidate"?, "reason"?}.
type sigMsg struct {
	Type      string `json:"type"`
	Code      string `json:"code,omitempty"`
	Token     string `json:"token,omitempty"`
	SDP       string `json:"sdp,omitempty"`
	Candidate string `json:"candidate,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// signaler is the internal signaling abstraction. connect performs the relay
// rendezvous (create/join) and returns once the peer has joined; send/recv move
// per-peer signaling messages (offer/answer/ice); close tears the transport
// down idempotently. Tests inject an in-process fake implementing this.
type signaler interface {
	connect(ctx context.Context) error
	send(ctx context.Context, m sigMsg) error
	recv(ctx context.Context) (sigMsg, error)
	close() error
}

// errPeerLeft indicates the remote peer left the room or the relay closed.
var errPeerLeft = errors.New("p2p: peer left")

// relayError maps a relay {"type":"error","reason":...} frame to a Go error.
func relayError(reason string) error {
	switch reason {
	case "room_exists":
		return errors.New("p2p signaling: pairing code already in use (room_exists)")
	case "no_room":
		return errors.New("p2p signaling: no room for pairing code (no_room)")
	case "room_full":
		return errors.New("p2p signaling: room already has two peers (room_full)")
	case "bad_message":
		return errors.New("p2p signaling: relay rejected message (bad_message)")
	case "expired":
		return errors.New("p2p signaling: pairing code expired (expired)")
	case "unauthorized":
		return errors.New("p2p signaling: relay rejected the room authorization (unauthorized) — the token expired or your plan does not allow P2P")
	case "":
		return errors.New("p2p signaling: relay error")
	default:
		return fmt.Errorf("p2p signaling: relay error (%s)", reason)
	}
}

// wsSignaler is the production signaler: a WebSocket to SignalingURL + /v1/signal
// using github.com/coder/websocket (the same library the relay uses).
type wsSignaler struct {
	url   string
	code  string
	token string
	role  Role

	conn *websocket.Conn

	writeMu   sync.Mutex // serialize writes on the conn
	closeOnce sync.Once
	closeErr  error
}

func newWSSignaler(cfg RelayConfig, role Role) *wsSignaler {
	return &wsSignaler{url: signalURL(cfg.SignalingURL), code: cfg.PairingCode, token: cfg.RoomToken, role: role}
}

// signalURL joins the relay base URL with the /v1/signal path.
func signalURL(base string) string {
	return strings.TrimRight(base, "/") + "/v1/signal"
}

func (w *wsSignaler) connect(ctx context.Context) error {
	conn, _, err := websocket.Dial(ctx, w.url, nil)
	if err != nil {
		return fmt.Errorf("p2p signaling: dial %s: %w", w.url, err)
	}
	// Allow larger control frames for SDP-carrying messages.
	conn.SetReadLimit(1 << 20)
	w.conn = conn

	if w.role == Sender {
		if err := w.send(ctx, sigMsg{Type: "create", Code: w.code, Token: w.token}); err != nil {
			return err
		}
		m, err := w.recv(ctx)
		if err != nil {
			return err
		}
		if m.Type == "error" {
			return relayError(m.Reason)
		}
		if m.Type != "created" {
			return fmt.Errorf("p2p signaling: expected created, got %q", m.Type)
		}
		// Wait for the receiver to join.
		m, err = w.recv(ctx)
		if err != nil {
			return err
		}
		if m.Type == "error" {
			return relayError(m.Reason)
		}
		if m.Type != "peer-joined" {
			return fmt.Errorf("p2p signaling: expected peer-joined, got %q", m.Type)
		}
		return nil
	}

	// Receiver.
	if err := w.send(ctx, sigMsg{Type: "join", Code: w.code, Token: w.token}); err != nil {
		return err
	}
	m, err := w.recv(ctx)
	if err != nil {
		return err
	}
	if m.Type == "error" {
		return relayError(m.Reason)
	}
	if m.Type != "peer-joined" {
		return fmt.Errorf("p2p signaling: expected peer-joined, got %q", m.Type)
	}
	return nil
}

func (w *wsSignaler) send(ctx context.Context, m sigMsg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("p2p signaling: marshal %s: %w", m.Type, err)
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if err := w.conn.Write(ctx, websocket.MessageText, b); err != nil {
		return fmt.Errorf("p2p signaling: write %s: %w", m.Type, err)
	}
	return nil
}

func (w *wsSignaler) recv(ctx context.Context) (sigMsg, error) {
	_, b, err := w.conn.Read(ctx)
	if err != nil {
		return sigMsg{}, fmt.Errorf("p2p signaling: read: %w", err)
	}
	var m sigMsg
	if err := json.Unmarshal(b, &m); err != nil {
		return sigMsg{}, fmt.Errorf("p2p signaling: decode: %w", err)
	}
	return m, nil
}

func (w *wsSignaler) close() error {
	w.closeOnce.Do(func() {
		if w.conn == nil {
			return
		}
		// Best-effort graceful bye, then close.
		ctx, cancel := context.WithCancel(context.Background())
		_ = w.send(ctx, sigMsg{Type: "bye"})
		cancel()
		w.closeErr = w.conn.Close(websocket.StatusNormalClosure, "bye")
		if w.closeErr != nil && errorIsAlreadyClosed(w.closeErr) {
			w.closeErr = nil
		}
	})
	return w.closeErr
}

func errorIsAlreadyClosed(err error) bool {
	var ce websocket.CloseError
	return errors.As(err, &ce) || errors.Is(err, http.ErrServerClosed)
}
