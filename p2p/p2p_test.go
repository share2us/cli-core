package p2p

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeSignaler is an in-process signaler that pipes signaling frames directly
// to its peer, so a sender and receiver session can complete a real pion
// negotiation without any relay or network. A pair is created by newFakePair.
type fakeSignaler struct {
	// in delivers frames sent by the peer; out is the peer's in.
	in  chan sigMsg
	out chan sigMsg

	// joined is closed once both endpoints have called connect (rendezvous).
	joined chan struct{}
	// ready is a shared barrier: both endpoints wait on it.
	barrier *sync.WaitGroup

	closeOnce sync.Once
	done      chan struct{}
}

// newFakePair returns two connected fake signalers (sender side, receiver side).
func newFakePair() (*fakeSignaler, *fakeSignaler) {
	a2b := make(chan sigMsg, 64)
	b2a := make(chan sigMsg, 64)
	var wg sync.WaitGroup
	wg.Add(2)
	shared := make(chan struct{})
	sender := &fakeSignaler{in: b2a, out: a2b, joined: shared, barrier: &wg, done: make(chan struct{})}
	receiver := &fakeSignaler{in: a2b, out: b2a, joined: shared, barrier: &wg, done: make(chan struct{})}
	return sender, receiver
}

func (f *fakeSignaler) connect(ctx context.Context) error {
	// Rendezvous: both sides must arrive. Respect ctx cancellation.
	f.barrier.Done()
	waitDone := make(chan struct{})
	go func() {
		f.barrier.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-f.done:
		return errors.New("fake signaler closed")
	}
}

func (f *fakeSignaler) send(ctx context.Context, m sigMsg) error {
	select {
	case f.out <- m:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-f.done:
		return errors.New("fake signaler closed")
	}
}

func (f *fakeSignaler) recv(ctx context.Context) (sigMsg, error) {
	select {
	case m := <-f.in:
		return m, nil
	case <-ctx.Done():
		return sigMsg{}, ctx.Err()
	case <-f.done:
		return sigMsg{}, errors.New("fake signaler closed")
	}
}

func (f *fakeSignaler) close() error {
	f.closeOnce.Do(func() {
		// Mirror the relay: notify the peer we left before closing, so the
		// other session's runSignaling observes the disconnect (best-effort).
		select {
		case f.out <- sigMsg{Type: "bye"}:
		default:
		}
		close(f.done)
	})
	return nil
}

// connectPair wires up a sender+receiver session over an in-process fake
// signaler and returns them connected (data channel open on both sides).
func connectPair(t *testing.T) (*webrtcSession, *webrtcSession) {
	t.Helper()
	sigS, sigR := newFakePair()

	cfg := RelayConfig{PairingCode: "S2S-TEST-CODE"}
	ss, err := newWebRTCSession(cfg, Sender, sigS)
	if err != nil {
		t.Fatalf("new sender: %v", err)
	}
	rs, err := newWebRTCSession(cfg, Receiver, sigR)
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}
	sender := ss.(*webrtcSession)
	receiver := rs.(*webrtcSession)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	var sErr, rErr error
	go func() { defer wg.Done(); sErr = sender.Connect(ctx) }()
	go func() { defer wg.Done(); rErr = receiver.Connect(ctx) }()
	wg.Wait()
	if sErr != nil {
		t.Fatalf("sender connect: %v", sErr)
	}
	if rErr != nil {
		t.Fatalf("receiver connect: %v", rErr)
	}
	return sender, receiver
}

// deterministicPayload builds a reproducible byte pattern of length n.
func deterministicPayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*31 + 7) & 0xff)
	}
	return b
}

func transfer(t *testing.T, sender, receiver *webrtcSession, payload []byte) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var got bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	var sErr, rErr error
	go func() {
		defer wg.Done()
		sErr = sender.Send(ctx, bytes.NewReader(payload))
		if sErr == nil {
			// Mirror the CLI: close after sending so the receiver's post-ACK
			// linger ends promptly instead of waiting out lingerTimeout.
			_ = sender.Close()
		}
	}()
	go func() {
		defer wg.Done()
		rErr = receiver.Receive(ctx, &got)
	}()
	wg.Wait()
	if sErr != nil {
		t.Fatalf("send: %v", sErr)
	}
	if rErr != nil {
		t.Fatalf("receive: %v", rErr)
	}
	return got.Bytes()
}

func TestTransferMultiChunk(t *testing.T) {
	sender, receiver := connectPair(t)
	defer sender.Close()
	defer receiver.Close()

	payload := deterministicPayload(1 << 20) // 1 MiB, many 16 KiB chunks
	got := transfer(t, sender, receiver, payload)
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestTransferSmallPayload(t *testing.T) {
	sender, receiver := connectPair(t)
	defer sender.Close()
	defer receiver.Close()

	payload := []byte("hello share2us p2p")
	got := transfer(t, sender, receiver, payload)
	if !bytes.Equal(got, payload) {
		t.Fatalf("small payload mismatch: got %q want %q", got, payload)
	}
}

func TestTransferEmptyPayload(t *testing.T) {
	sender, receiver := connectPair(t)
	defer sender.Close()
	defer receiver.Close()

	got := transfer(t, sender, receiver, []byte{})
	if len(got) != 0 {
		t.Fatalf("empty payload mismatch: got %d bytes, want 0", len(got))
	}
}

func TestConnectContextCancel(t *testing.T) {
	// Only the sender connects; the receiver never joins, so the rendezvous
	// (and thus Connect) blocks until ctx is cancelled.
	sigS, _ := newFakePair()
	ss, err := newWebRTCSession(RelayConfig{PairingCode: "S2S-CANCEL"}, Sender, sigS)
	if err != nil {
		t.Fatalf("new sender: %v", err)
	}
	sender := ss.(*webrtcSession)
	defer sender.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- sender.Connect(ctx) }()

	// Cancel mid-connect.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Connect returned nil after cancel, want error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Connect error = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Connect did not return promptly after ctx cancel")
	}
}

func TestCloseIdempotent(t *testing.T) {
	sender, receiver := connectPair(t)
	if err := sender.Close(); err != nil {
		t.Fatalf("first sender close: %v", err)
	}
	if err := sender.Close(); err != nil {
		t.Fatalf("second sender close: %v", err)
	}
	if err := receiver.Close(); err != nil {
		t.Fatalf("receiver close: %v", err)
	}
}

// connectPairWithSecrets connects a sender+receiver over the fake signaler with
// the given pairing secrets, returning both sessions and their Connect errors.
func connectPairWithSecrets(t *testing.T, senderSecret, receiverSecret string) (*webrtcSession, *webrtcSession, error, error) {
	t.Helper()
	sigS, sigR := newFakePair()
	ss, err := newWebRTCSession(RelayConfig{PairingCode: "S2S-SAS-ROOM", Secret: senderSecret}, Sender, sigS)
	if err != nil {
		t.Fatalf("new sender: %v", err)
	}
	rs, err := newWebRTCSession(RelayConfig{PairingCode: "S2S-SAS-ROOM", Secret: receiverSecret}, Receiver, sigR)
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}
	sender := ss.(*webrtcSession)
	receiver := rs.(*webrtcSession)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	var sErr, rErr error
	go func() { defer wg.Done(); sErr = sender.Connect(ctx) }()
	go func() { defer wg.Done(); rErr = receiver.Connect(ctx) }()
	wg.Wait()
	return sender, receiver, sErr, rErr
}

// TestVerifyPeerMatchingSecret: identical secrets → SAS passes → transfer works.
func TestVerifyPeerMatchingSecret(t *testing.T) {
	sender, receiver, sErr, rErr := connectPairWithSecrets(t, "correct-horse-battery", "correct-horse-battery")
	if sErr != nil || rErr != nil {
		t.Fatalf("connect with matching secret: sender=%v receiver=%v", sErr, rErr)
	}
	defer sender.Close()
	defer receiver.Close()

	payload := deterministicPayload(64 * 1024)
	got := transfer(t, sender, receiver, payload)
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch after verified connect")
	}
}

// TestVerifyPeerMismatchedSecret: different secrets (as a MITM/wrong-code would
// produce) → both sides' SAS MACs diverge → Connect fails on both.
func TestVerifyPeerMismatchedSecret(t *testing.T) {
	sender, receiver, sErr, rErr := connectPairWithSecrets(t, "secret-alpha", "secret-bravo")
	if sender != nil {
		defer sender.Close()
	}
	if receiver != nil {
		defer receiver.Close()
	}
	if sErr == nil || rErr == nil {
		t.Fatalf("mismatched secrets must fail verification on both sides: sender=%v receiver=%v", sErr, rErr)
	}
}

func TestNewSessionSurface(t *testing.T) {
	// Public constructor still works and returns a usable Session value.
	s, err := NewSession(RelayConfig{
		SignalingURL: "wss://relay.share2.us",
		TURNServers:  []string{"turn:turn.share2.us"},
		PairingCode:  "S2S-ABCD-EFGH",
	}, Sender)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if s == nil {
		t.Fatal("NewSession returned nil session")
	}
}
