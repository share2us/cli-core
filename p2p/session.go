package p2p

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

const (
	// dataChannelLabel is the single ordered/reliable channel used for the
	// file transfer.
	dataChannelLabel = "s2u-file"
	// ctrlChannelLabel is a small ordered/reliable channel used only for the
	// SAS peer-verification handshake (one MAC each way) before bytes flow.
	ctrlChannelLabel = "s2u-ctrl"

	// chunkSize is the payload size per framed data-channel message (16 KiB).
	chunkSize = 16 * 1024

	// maxBufferedAmount caps in-flight SCTP bytes on the sender before we wait
	// for the buffer to drain (backpressure).
	maxBufferedAmount = 1 << 20 // 1 MiB
	// bufferedAmountLowThreshold is when OnBufferedAmountLow fires.
	bufferedAmountLowThreshold = 512 * 1024

	// ackTimeout bounds how long the sender waits for the receiver's completion
	// ACK after the last byte is drained.
	ackTimeout = 30 * time.Second

	// lingerTimeout bounds how long the receiver keeps the connection alive
	// after ACKing, so the sender reliably receives the ACK and closes first.
	lingerTimeout = 10 * time.Second
)

// ackMessage is the receiver→sender end-of-transfer acknowledgement sent over
// the control channel once the whole stream has been received. It lets the
// sender report clean success instead of racing the receiver's disconnect.
var ackMessage = []byte("s2u-ack")

// frame carries one decoded data-channel message from the pion read goroutine
// to Receive. eof marks the zero-length terminator.
type frame struct {
	data []byte
	eof  bool
}

// webrtcSession is the real pion-backed Session.
type webrtcSession struct {
	cfg  RelayConfig
	role Role
	sig  signaler

	sessionCtx context.Context
	cancel     context.CancelFunc

	pc     *webrtc.PeerConnection
	dc     *webrtc.DataChannel
	dcCtrl *webrtc.DataChannel

	dcOpen   chan struct{} // closed when the file data channel is open+ready
	ctrlOpen chan struct{} // closed when the control channel is open+ready
	ctrlRecv chan []byte   // one inbound control message (the peer's SAS MAC)

	// backpressure: OnBufferedAmountLow pokes bufLow.
	bufLow chan struct{}

	// receiver-side reassembly queue.
	recvCh chan frame

	// remote-description / trickle-ICE ordering.
	mu        sync.Mutex
	remoteSet bool
	pendingIC []webrtc.ICECandidateInit

	// fatal signaling error (peer-left / relay error / transport close).
	failOnce sync.Once
	failCh   chan struct{}
	failErr  error

	closeOnce sync.Once
	closeErr  error
}

// newWebRTCSession builds a session. If sig is nil, the production WebSocket
// signaler is used; tests pass an in-process fake.
func newWebRTCSession(cfg RelayConfig, role Role, sig signaler) (Session, error) {
	if role != Sender && role != Receiver {
		return nil, fmt.Errorf("p2p: invalid role %d", role)
	}
	if sig == nil {
		sig = newWSSignaler(cfg, role)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &webrtcSession{
		cfg:        cfg,
		role:       role,
		sig:        sig,
		sessionCtx: ctx,
		cancel:     cancel,
		dcOpen:     make(chan struct{}),
		ctrlOpen:   make(chan struct{}),
		ctrlRecv:   make(chan []byte, 1),
		bufLow:     make(chan struct{}, 1),
		recvCh:     make(chan frame, 128),
		failCh:     make(chan struct{}),
	}, nil
}

// newPeerConnection builds the pion API + PeerConnection. mDNS is disabled so
// host-candidate gathering is deterministic (important for hermetic tests).
func (s *webrtcSession) newPeerConnection() (*webrtc.PeerConnection, error) {
	se := webrtc.SettingEngine{}
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(se))

	cfg := webrtc.Configuration{}
	// Credentialed ICE servers come from the API's room-authorization response
	// (time-limited coturn REST credentials). Bare --turn URLs are also honored.
	// Empty means host candidates only (fine on a LAN / loopback, but a peer
	// behind a symmetric NAT will fail to connect without TURN).
	for _, srv := range s.cfg.ICEServers {
		if len(srv.URLs) == 0 {
			continue
		}
		ice := webrtc.ICEServer{URLs: srv.URLs}
		if srv.Username != "" {
			ice.Username = srv.Username
			ice.Credential = srv.Credential
			ice.CredentialType = webrtc.ICECredentialTypePassword
		}
		cfg.ICEServers = append(cfg.ICEServers, ice)
	}
	if len(s.cfg.TURNServers) > 0 {
		cfg.ICEServers = append(cfg.ICEServers, webrtc.ICEServer{URLs: s.cfg.TURNServers})
	}
	return api.NewPeerConnection(cfg)
}

func (s *webrtcSession) Connect(ctx context.Context) error {
	if s.sig == nil {
		return ErrNotImplemented
	}

	// 1. Relay rendezvous: create/join, block until the peer has joined.
	if err := s.sig.connect(ctx); err != nil {
		return err
	}

	// 2. Build the peer connection.
	pc, err := s.newPeerConnection()
	if err != nil {
		return fmt.Errorf("p2p: new peer connection: %w", err)
	}
	s.pc = pc

	// Trickle ICE outbound; ignore the final nil candidate.
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		init := c.ToJSON()
		b, err := json.Marshal(init)
		if err != nil {
			return
		}
		_ = s.sig.send(s.sessionCtx, sigMsg{Type: "ice", Candidate: string(b)})
	})

	// Fail the session if ICE goes to a terminal failed/closed state.
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		if state == webrtc.ICEConnectionStateFailed {
			s.fail(errors.New("p2p: ICE connection failed"))
		}
	})

	switch s.role {
	case Sender:
		dc, err := s.setupSenderChannel()
		if err != nil {
			return err
		}
		s.dc = dc
		ctrl, err := s.setupSenderCtrlChannel()
		if err != nil {
			return err
		}
		s.dcCtrl = ctrl
		// Start reading signaling (the answer + trickled ICE) before sending
		// the offer so nothing is missed.
		go s.runSignaling()

		offer, err := pc.CreateOffer(nil)
		if err != nil {
			return fmt.Errorf("p2p: create offer: %w", err)
		}
		if err := pc.SetLocalDescription(offer); err != nil {
			return fmt.Errorf("p2p: set local description: %w", err)
		}
		if err := s.sig.send(ctx, sigMsg{Type: "offer", SDP: offer.SDP}); err != nil {
			return err
		}

	case Receiver:
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			switch dc.Label() {
			case dataChannelLabel:
				s.dc = dc
				s.setupReceiverChannel(dc)
			case ctrlChannelLabel:
				s.dcCtrl = dc
				s.setupCtrlChannel(dc)
			}
		})
		go s.runSignaling()
	}

	// 3. Wait for both channels to open (or ctx / fatal signaling error).
	for _, ch := range []chan struct{}{s.dcOpen, s.ctrlOpen} {
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.failCh:
			return s.failErr
		case <-s.sessionCtx.Done():
			return context.Canceled
		}
	}

	// 4. SAS peer verification over the pairing-code secret before any bytes
	// flow — detects a MITM relay that swapped DTLS fingerprints.
	if err := s.verifyPeer(ctx); err != nil {
		return err
	}
	return nil
}

// setupSenderChannel creates the ordered/reliable data channel and wires
// backpressure + open notification.
func (s *webrtcSession) setupSenderChannel() (*webrtc.DataChannel, error) {
	ordered := true
	dc, err := s.pc.CreateDataChannel(dataChannelLabel, &webrtc.DataChannelInit{Ordered: &ordered})
	if err != nil {
		return nil, fmt.Errorf("p2p: create data channel: %w", err)
	}
	dc.SetBufferedAmountLowThreshold(bufferedAmountLowThreshold)
	dc.OnBufferedAmountLow(func() {
		select {
		case s.bufLow <- struct{}{}:
		default:
		}
	})
	dc.OnOpen(func() { s.markOpen() })
	return dc, nil
}

// setupReceiverChannel wires message reassembly + open notification.
func (s *webrtcSession) setupReceiverChannel(dc *webrtc.DataChannel) {
	dc.OnOpen(func() { s.markOpen() })
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		f, err := decodeFrame(msg.Data)
		if err != nil {
			s.fail(err)
			return
		}
		select {
		case s.recvCh <- f:
		case <-s.sessionCtx.Done():
		}
	})
}

func (s *webrtcSession) markOpen() {
	// dcOpen is closed exactly once even if OnOpen races.
	select {
	case <-s.dcOpen:
	default:
		close(s.dcOpen)
	}
}

func (s *webrtcSession) markCtrlOpen() {
	select {
	case <-s.ctrlOpen:
	default:
		close(s.ctrlOpen)
	}
}

// setupSenderCtrlChannel creates the control channel (sender side). Both roles
// use setupCtrlChannel to wire open + inbound-MAC handling.
func (s *webrtcSession) setupSenderCtrlChannel() (*webrtc.DataChannel, error) {
	ordered := true
	dc, err := s.pc.CreateDataChannel(ctrlChannelLabel, &webrtc.DataChannelInit{Ordered: &ordered})
	if err != nil {
		return nil, fmt.Errorf("p2p: create control channel: %w", err)
	}
	s.setupCtrlChannel(dc)
	return dc, nil
}

// setupCtrlChannel wires the control channel's open signal and delivers the one
// inbound control message (the peer's SAS MAC) to ctrlRecv.
func (s *webrtcSession) setupCtrlChannel(dc *webrtc.DataChannel) {
	dc.OnOpen(func() { s.markCtrlOpen() })
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		b := make([]byte, len(msg.Data))
		copy(b, msg.Data)
		select {
		case s.ctrlRecv <- b:
		case <-s.sessionCtx.Done():
		}
	})
}

// runSignaling dispatches inbound signaling messages for the session lifetime.
func (s *webrtcSession) runSignaling() {
	for {
		m, err := s.sig.recv(s.sessionCtx)
		if err != nil {
			// Closed transport during/after teardown is expected.
			select {
			case <-s.sessionCtx.Done():
				return
			default:
			}
			s.fail(err)
			return
		}
		switch m.Type {
		case "offer":
			if err := s.handleOffer(m.SDP); err != nil {
				s.fail(err)
				return
			}
		case "answer":
			if err := s.handleAnswer(m.SDP); err != nil {
				s.fail(err)
				return
			}
		case "ice":
			if err := s.handleICE(m.Candidate); err != nil {
				s.fail(err)
				return
			}
		case "peer-left", "bye":
			s.fail(errPeerLeft)
			return
		case "error":
			s.fail(relayError(m.Reason))
			return
		default:
			// Ignore unknown/relay-control frames.
		}
	}
}

func (s *webrtcSession) handleOffer(sdp string) error {
	if err := s.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer, SDP: sdp,
	}); err != nil {
		return fmt.Errorf("p2p: set remote offer: %w", err)
	}
	s.flushPendingICE()
	answer, err := s.pc.CreateAnswer(nil)
	if err != nil {
		return fmt.Errorf("p2p: create answer: %w", err)
	}
	if err := s.pc.SetLocalDescription(answer); err != nil {
		return fmt.Errorf("p2p: set local answer: %w", err)
	}
	return s.sig.send(s.sessionCtx, sigMsg{Type: "answer", SDP: answer.SDP})
}

func (s *webrtcSession) handleAnswer(sdp string) error {
	if err := s.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer, SDP: sdp,
	}); err != nil {
		return fmt.Errorf("p2p: set remote answer: %w", err)
	}
	s.flushPendingICE()
	return nil
}

func (s *webrtcSession) handleICE(candidate string) error {
	if candidate == "" {
		return nil // ignore empty final candidate
	}
	var init webrtc.ICECandidateInit
	if err := json.Unmarshal([]byte(candidate), &init); err != nil {
		return fmt.Errorf("p2p: decode ICE candidate: %w", err)
	}
	s.mu.Lock()
	if !s.remoteSet {
		s.pendingIC = append(s.pendingIC, init)
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	return s.pc.AddICECandidate(init)
}

// flushPendingICE applies candidates buffered before the remote description
// was set, and marks the remote as set so future candidates apply directly.
func (s *webrtcSession) flushPendingICE() {
	s.mu.Lock()
	s.remoteSet = true
	pending := s.pendingIC
	s.pendingIC = nil
	s.mu.Unlock()
	for _, c := range pending {
		_ = s.pc.AddICECandidate(c)
	}
}

// verifyPeer runs an authenticated short-authentication-string (SAS) check over
// the control channel, right after both channels open and before any bytes
// flow. Each peer computes a MAC, keyed by the out-of-band pairing secret, over
// a channel binding derived from BOTH DTLS certificate fingerprints (as that
// peer observed them), then they exchange and compare MACs.
//
// Under an honest connection both peers see the same fingerprint pair, so the
// canonical binding — and therefore the MAC — is identical. A relay that
// terminated DTLS on each side (a MITM) would make each peer see a DIFFERENT
// remote fingerprint, so the bindings and MACs diverge and verification fails.
// The relay cannot forge a matching MAC because it never learns the secret (the
// secret is the private half of the pairing code, shared out of band, never
// sent to the relay). An empty secret disables the check.
func (s *webrtcSession) verifyPeer(ctx context.Context) error {
	secret := strings.TrimSpace(s.cfg.Secret)
	if secret == "" {
		if s.cfg.Insecure {
			return nil // explicit opt-out (test-only); no SAS verification
		}
		return errors.New("p2p: refusing to connect without a peer-verification secret")
	}
	if s.dcCtrl == nil {
		return errors.New("p2p: control channel unavailable for verification")
	}
	localFP, err := fingerprintFromSDP(s.pc.LocalDescription())
	if err != nil {
		return err
	}
	remoteFP, err := fingerprintFromSDP(s.pc.RemoteDescription())
	if err != nil {
		return err
	}
	mac := sasMAC(secret, channelBinding(localFP, remoteFP))
	if err := s.dcCtrl.Send(mac); err != nil {
		return fmt.Errorf("p2p: send verification: %w", err)
	}

	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case peerMAC := <-s.ctrlRecv:
		if !hmac.Equal(peerMAC, mac) {
			return errors.New("p2p: peer verification failed — the pairing code did not match, or the connection was tampered with")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.failCh:
		return s.failErr
	case <-s.sessionCtx.Done():
		return errors.New("p2p: session closed")
	case <-timer.C:
		return errors.New("p2p: peer verification timed out")
	}
}

// fingerprintFromSDP extracts the first DTLS fingerprint (algo + hex) from an
// SDP. pion advertises it as `a=fingerprint:sha-256 AA:BB:...`.
func fingerprintFromSDP(desc *webrtc.SessionDescription) (string, error) {
	if desc == nil {
		return "", errors.New("p2p: missing session description for verification")
	}
	for _, line := range strings.Split(desc.SDP, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "a=fingerprint:"); ok {
			return strings.TrimSpace(v), nil
		}
	}
	return "", errors.New("p2p: no DTLS fingerprint in SDP")
}

// channelBinding combines the two DTLS fingerprints order-independently so both
// peers derive the same value from the same (honest) connection.
func channelBinding(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "|" + b
}

// sasMAC is a 16-byte HMAC-SHA256 over the channel binding, keyed by the secret
// and domain-separated by a version tag.
func sasMAC(secret, binding string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("s2u-sas-v1\x00"))
	m.Write([]byte(binding))
	return m.Sum(nil)[:16]
}

func (s *webrtcSession) Send(ctx context.Context, src io.Reader) error {
	if s.role != Sender {
		return errors.New("p2p: Send called on a receiver session")
	}
	if s.dc == nil {
		return errors.New("p2p: Send before Connect")
	}

	buf := make([]byte, chunkSize)
	for {
		if err := s.ctxErr(ctx); err != nil {
			return err
		}
		n, err := src.Read(buf)
		if n > 0 {
			if werr := s.writeFrame(ctx, buf[:n]); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("p2p: read source: %w", err)
		}
	}

	// EOF terminator (a zero-length frame).
	if err := s.writeFrame(ctx, nil); err != nil {
		return err
	}
	// Wait for the SCTP buffer to drain so we don't close mid-flight.
	if err := s.drain(ctx); err != nil {
		return err
	}
	// Wait for the receiver's completion ACK so a successful transfer reports
	// success even though the receiver disconnects right after receiving.
	return s.awaitAck(ctx)
}

// awaitAck waits for the receiver's end-of-transfer ACK on the control channel.
// A peer-left that races the ACK does not fail the transfer: if the ACK also
// arrived it is preferred (the bytes were fully delivered).
func (s *webrtcSession) awaitAck(ctx context.Context) error {
	select {
	case <-s.ctrlRecv:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.sessionCtx.Done():
		return errors.New("p2p: session closed")
	case <-s.failCh:
		select {
		case <-s.ctrlRecv:
			return nil // ACK arrived alongside the peer-left — delivery completed
		default:
			return s.failErr
		}
	case <-time.After(ackTimeout):
		return errors.New("p2p: timed out waiting for the receiver to confirm receipt")
	}
}

// sendAck notifies the sender that the whole stream was received.
func (s *webrtcSession) sendAck() {
	if s.dcCtrl != nil {
		_ = s.dcCtrl.Send(ackMessage)
	}
}

// lingerForClose keeps the receiver's connection alive after it has ACKed, until
// the sender closes (peer-left/bye) or a timeout — ensuring the ACK is delivered
// and the sender tears down first, so neither side reports a spurious peer-left.
func (s *webrtcSession) lingerForClose(ctx context.Context) {
	select {
	case <-s.failCh:
	case <-ctx.Done():
	case <-s.sessionCtx.Done():
	case <-time.After(lingerTimeout):
	}
}

// writeFrame writes one length-prefixed frame, applying backpressure when the
// SCTP send buffer is full.
func (s *webrtcSession) writeFrame(ctx context.Context, payload []byte) error {
	for s.dc.BufferedAmount() >= maxBufferedAmount {
		select {
		case <-s.bufLow:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.failCh:
			return s.failErr
		case <-s.sessionCtx.Done():
			return errors.New("p2p: session closed")
		}
	}
	msg := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(msg[:4], uint32(len(payload)))
	copy(msg[4:], payload)
	if err := s.dc.Send(msg); err != nil {
		return fmt.Errorf("p2p: data channel send: %w", err)
	}
	return nil
}

// drain waits until the data channel's send buffer is empty.
func (s *webrtcSession) drain(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for s.dc.BufferedAmount() > 0 {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.failCh:
			return s.failErr
		case <-s.sessionCtx.Done():
			return errors.New("p2p: session closed")
		}
	}
	return nil
}

func (s *webrtcSession) Receive(ctx context.Context, dst io.Writer) error {
	if s.role != Receiver {
		return errors.New("p2p: Receive called on a sender session")
	}
	if s.dc == nil {
		return errors.New("p2p: Receive before Connect")
	}
	for {
		select {
		case f := <-s.recvCh:
			if f.eof {
				s.sendAck()
				s.lingerForClose(ctx)
				return nil
			}
			if _, err := dst.Write(f.data); err != nil {
				return fmt.Errorf("p2p: write dest: %w", err)
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-s.failCh:
			// If a fatal error arrived but frames may still be queued, prefer
			// draining a pending frame; otherwise surface the error.
			select {
			case f := <-s.recvCh:
				if f.eof {
					s.sendAck()
					return nil
				}
				if _, err := dst.Write(f.data); err != nil {
					return fmt.Errorf("p2p: write dest: %w", err)
				}
			default:
				return s.failErr
			}
		case <-s.sessionCtx.Done():
			return errors.New("p2p: session closed")
		}
	}
}

func (s *webrtcSession) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		var errs []error
		if s.dc != nil {
			if err := s.dc.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if s.dcCtrl != nil {
			if err := s.dcCtrl.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if s.pc != nil {
			if err := s.pc.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if s.sig != nil {
			if err := s.sig.close(); err != nil {
				errs = append(errs, err)
			}
		}
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

// fail records the first fatal session error and wakes any waiters.
func (s *webrtcSession) fail(err error) {
	s.failOnce.Do(func() {
		s.failErr = err
		close(s.failCh)
	})
}

// ctxErr returns a non-nil error if ctx, the session, or a fatal signaling
// error has fired.
func (s *webrtcSession) ctxErr(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.failCh:
		return s.failErr
	case <-s.sessionCtx.Done():
		return errors.New("p2p: session closed")
	default:
		return nil
	}
}

// decodeFrame parses one data-channel message: a 4-byte big-endian length
// prefix followed by that many payload bytes. Length 0 is the EOF terminator.
func decodeFrame(msg []byte) (frame, error) {
	if len(msg) < 4 {
		return frame{}, fmt.Errorf("p2p: short frame (%d bytes)", len(msg))
	}
	n := binary.BigEndian.Uint32(msg[:4])
	if n == 0 {
		return frame{eof: true}, nil
	}
	if int(n) != len(msg)-4 {
		return frame{}, fmt.Errorf("p2p: frame length mismatch: hdr=%d body=%d", n, len(msg)-4)
	}
	// Copy: pion may reuse the underlying buffer after OnMessage returns.
	data := make([]byte, n)
	copy(data, msg[4:])
	return frame{data: data}, nil
}
