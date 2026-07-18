// Package p2p implements the Share2Us peer-to-peer streaming transport
// (Phase 3): a single ordered/reliable WebRTC data channel between two peers,
// with SDP/ICE signaling brokered by a lightweight relay WebSocket.
//
// Wire framing over the "s2u-file" data channel: the stream is a sequence of
// length-prefixed chunks. Each frame is a 4-byte big-endian uint32 length
// followed by that many payload bytes. A frame with length 0 is the EOF
// terminator; the sender writes it last and the receiver stops on it. Chunks
// are at most chunkSize (16 KiB) of payload.
package p2p

import (
	"context"
	"errors"
	"io"
)

// Role selects whether a Session is the offering sender or the answering
// receiver.
type Role int

const (
	// Sender creates the data channel and the SDP offer, and streams bytes.
	Sender Role = iota
	// Receiver answers the offer and reassembles the received stream.
	Receiver
)

// ErrNotImplemented is returned only for genuinely unsupported paths (e.g. a
// Session constructed without a usable signaler). The real transport below no
// longer returns it for the happy path.
var ErrNotImplemented = errors.New("p2p streaming not implemented for this configuration")

// Session is the transport surface the CLI depends on. Connect performs
// signaling + ICE and opens the data channel; Send/Receive move bytes; Close
// tears everything down idempotently.
type Session interface {
	Connect(ctx context.Context) error
	Send(ctx context.Context, src io.Reader) error
	Receive(ctx context.Context, dst io.Writer) error
	Close() error
}

// ICEServer is a STUN/TURN server with optional time-limited credentials, as
// issued by the API's room-authorization endpoint.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// RelayConfig configures the signaling relay and ICE.
type RelayConfig struct {
	// SignalingURL is the relay base URL (e.g. wss://relay.share2.us). The
	// WebSocket connects to this URL + "/v1/signal".
	SignalingURL string
	// TURNServers are credential-less turn: URLs (from the --turn flag). Empty
	// means host/loopback candidates only.
	TURNServers []string
	// ICEServers come from the API's room-authorization response and carry
	// time-limited TURN credentials. Preferred over TURNServers.
	ICEServers []ICEServer
	// RoomToken is the short-lived capability minted by the API authorizing this
	// (room, role) on the relay. The relay verifies it; without a valid token an
	// authorized relay rejects the create/join with "unauthorized".
	RoomToken string
	// PairingCode is the room code used to rendezvous on the relay. The relay
	// sees this, so it is NOT the confidentiality anchor.
	PairingCode string
	// Secret is the out-of-band shared secret (the private half of the full
	// pairing code, never sent to the relay). It keys the SAS peer verification
	// in Connect, so a MITM relay that swapped DTLS fingerprints is detected.
	// Empty disables verification (e.g. tests / secretless mode).
	Secret string
}

// --- Legacy exported signaling types (kept for API compatibility) ---
//
// These pre-date the real transport and are retained so the package's exported
// surface does not break. The internal signaling abstraction is the unexported
// `signaler` interface in signaling.go; new code should use that.

// Signaler is the legacy exported signaling interface. Deprecated: use the
// internal signaler abstraction.
type Signaler interface {
	CreateOffer(ctx context.Context) (Offer, error)
	AnswerOffer(ctx context.Context, offer Offer) (Answer, error)
	ExchangeICE(ctx context.Context, candidates ...ICECandidate) error
}

// Offer is a legacy SDP offer wrapper.
type Offer struct{ SDP string }

// Answer is a legacy SDP answer wrapper.
type Answer struct{ SDP string }

// ICECandidate is a legacy ICE candidate wrapper.
type ICECandidate struct{ Candidate string }

// NewSession builds a WebRTC session that signals over the relay WebSocket at
// cfg.SignalingURL and, on Connect, opens one ordered/reliable data channel
// named "s2u-file". The Sender creates the channel and offer; the Receiver
// answers. The returned Session is not safe for concurrent Connect calls but
// Close may be called from any goroutine.
func NewSession(cfg RelayConfig, role Role) (Session, error) {
	return newWebRTCSession(cfg, role, nil)
}
