package lanshare

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startReceiver runs Receive in a goroutine and returns the live ListenInfo plus
// a channel that yields the final result.
func startReceiver(t *testing.T, opts ReceiveOptions) (ListenInfo, <-chan recvOutcome, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	infoCh := make(chan ListenInfo, 1)
	outCh := make(chan recvOutcome, 1)
	userOnListen := opts.OnListen
	opts.OnListen = func(info ListenInfo) {
		if userOnListen != nil {
			userOnListen(info)
		}
		infoCh <- info
	}
	go func() {
		res, err := Receive(ctx, opts)
		outCh <- recvOutcome{res, err}
	}()
	select {
	case info := <-infoCh:
		return info, outCh, cancel
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("receiver did not start listening")
		return ListenInfo{}, nil, cancel
	}
}

type recvOutcome struct {
	res ReceiveResult
	err error
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestRoundTripPassword(t *testing.T) {
	dir := t.TempDir()
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", Password: "correct-horse-battery-staple", DestDir: dir,
	})
	defer cancel()
	if info.Mode != ModePassword {
		t.Fatalf("mode = %q, want password", info.Mode)
	}

	payload := randomBytes(t, 300*1024) // spans multiple 64 KiB chunks
	sum, err := Send(context.Background(), "hello.bin", int64(len(payload)), false,
		bytes.NewReader(payload), SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port), Password: "correct-horse-battery-staple"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if sum != sha256Hex(payload) {
		t.Fatalf("sender sha mismatch")
	}

	out := <-outCh
	if out.err != nil {
		t.Fatalf("Receive: %v", out.err)
	}
	if out.res.SHA256 != sha256Hex(payload) {
		t.Fatalf("receiver sha mismatch")
	}
	got, err := os.ReadFile(filepath.Join(dir, "hello.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("delivered bytes differ")
	}
}

func TestWrongPassword(t *testing.T) {
	dir := t.TempDir()
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", Password: "the-right-password", DestDir: dir,
	})
	defer cancel()

	_, err := Send(context.Background(), "x.bin", 4, false, bytes.NewReader([]byte("data")),
		SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port), Password: "a-wrong-password"})
	if err == nil {
		t.Fatal("expected Send to fail with wrong password")
	}
	// Receiver must NOT have written the file and should still be listening.
	if _, statErr := os.Stat(filepath.Join(dir, "x.bin")); statErr == nil {
		t.Fatal("file was written despite wrong password")
	}
	cancel()
	<-outCh // drains (ctx-cancel error expected)
}

func TestOpenModeNoPassword(t *testing.T) {
	dir := t.TempDir()
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir,
	})
	defer cancel()
	if info.Mode != ModeOpen {
		t.Fatalf("mode = %q, want open", info.Mode)
	}
	payload := []byte("open transfer, no password")
	if _, err := Send(context.Background(), "note.txt", int64(len(payload)), false,
		bytes.NewReader(payload), SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port)}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	out := <-outCh
	if out.err != nil {
		t.Fatalf("Receive: %v", out.err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "note.txt"))
	if !bytes.Equal(got, payload) {
		t.Fatal("delivered bytes differ")
	}
}

func TestFingerprintPinning(t *testing.T) {
	dir := t.TempDir()
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir,
	})
	defer cancel()

	// Wrong fingerprint must abort.
	_, err := Send(context.Background(), "a.txt", 3, false, bytes.NewReader([]byte("abc")),
		SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port), PinFingerprint: strings.Repeat("00", 32)})
	if err == nil {
		t.Fatal("expected Send to fail with wrong pinned fingerprint")
	}

	// Correct fingerprint succeeds.
	if _, err := Send(context.Background(), "a.txt", 3, false, bytes.NewReader([]byte("abc")),
		SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port), PinFingerprint: info.Fingerprint}); err != nil {
		t.Fatalf("Send with correct fingerprint: %v", err)
	}
	out := <-outCh
	if out.err != nil {
		t.Fatalf("Receive: %v", out.err)
	}
}

func TestOverwriteRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dup.bin"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir,
	})
	defer cancel()

	_, err := Send(context.Background(), "dup.bin", 3, false, bytes.NewReader([]byte("new")),
		SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port)})
	if err == nil {
		t.Fatal("expected Send to fail when file exists without --overwrite")
	}
	out := <-outCh // receiver returns terminal error on overwrite refusal
	if out.err == nil {
		t.Fatal("expected receiver to report overwrite refusal")
	}
	got, _ := os.ReadFile(filepath.Join(dir, "dup.bin"))
	if string(got) != "old" {
		t.Fatal("existing file was overwritten")
	}
}

func TestOverwriteReplaces(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dup.bin"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir, Overwrite: true,
	})
	defer cancel()

	if _, err := Send(context.Background(), "dup.bin", 3, false, bytes.NewReader([]byte("new")),
		SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port)}); err != nil {
		t.Fatalf("Send with --overwrite: %v", err)
	}
	out := <-outCh
	if out.err != nil {
		t.Fatalf("receiver error: %v", out.err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "dup.bin"))
	if string(got) != "new" {
		t.Fatalf("file content = %q, want %q", got, "new")
	}
}

func TestAllowIPAllowed(t *testing.T) {
	dir := t.TempDir()
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", AllowIPs: []string{"127.0.0.1"}, DestDir: dir,
	})
	defer cancel()
	if info.Mode != ModeAllowIP {
		t.Fatalf("mode = %q, want allow-ip", info.Mode)
	}
	if _, err := Send(context.Background(), "ip.txt", 2, false, bytes.NewReader([]byte("hi")),
		SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port)}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	out := <-outCh
	if out.err != nil {
		t.Fatalf("Receive: %v", out.err)
	}
}

func TestGeneratePassphrase(t *testing.T) {
	p, err := GeneratePassphrase(10)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Split(p, "-")); n != 10 {
		t.Fatalf("passphrase word count = %d, want 10 (%q)", n, p)
	}
	p2, _ := GeneratePassphrase(10)
	if p == p2 {
		t.Fatal("passphrases should be random")
	}
}

func TestPairingRoundTrip(t *testing.T) {
	info := ListenInfo{Port: 4321, Fingerprint: "abc123", Passphrase: "ten-word-pass", Mode: ModePassword}
	s := BuildPairingString("192.168.1.5", info)
	if !IsPairingString(s) {
		t.Fatalf("IsPairingString(%q) = false", s)
	}
	got, err := ParsePairingString(s)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "192.168.1.5" || got.Port != 4321 || got.Fingerprint != "abc123" || got.Password != "ten-word-pass" {
		t.Fatalf("parsed = %+v", got)
	}
	if got.Addr() != "192.168.1.5:4321" {
		t.Fatalf("Addr = %q", got.Addr())
	}
}

func TestTransferViaPairingString(t *testing.T) {
	dir := t.TempDir()
	var pairing string
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", DestDir: dir, // default => auto passphrase, password mode
		OnListen: func(i ListenInfo) { pairing = BuildPairingString("127.0.0.1", i) },
	})
	defer cancel()
	_ = info

	pi, err := ParsePairingString(pairing)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("delivered via pairing string")
	if _, err := Send(context.Background(), "paired.txt", int64(len(payload)), false,
		bytes.NewReader(payload), SendOptions{Dest: pi.Addr(), Password: pi.Password, PinFingerprint: pi.Fingerprint}); err != nil {
		t.Fatalf("Send via pairing: %v", err)
	}
	out := <-outCh
	if out.err != nil {
		t.Fatalf("Receive: %v", out.err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "paired.txt"))
	if !bytes.Equal(got, payload) {
		t.Fatal("delivered bytes differ")
	}
}

func TestTrustedPeerBypassesPassword(t *testing.T) {
	dir := t.TempDir()
	// Receiver has a password (for everyone) BUT trusts 127.0.0.1.
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", Password: "everyone-needs-this", TrustedIPs: []string{"127.0.0.1"}, DestDir: dir,
	})
	defer cancel()
	// Sender from the trusted IP sends with NO password and is accepted.
	payload := []byte("trusted, no password needed")
	if _, err := Send(context.Background(), "trusted.txt", int64(len(payload)), false,
		bytes.NewReader(payload), SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port)}); err != nil {
		t.Fatalf("trusted Send: %v", err)
	}
	out := <-outCh
	if out.err != nil {
		t.Fatalf("Receive: %v", out.err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "trusted.txt"))
	if !bytes.Equal(got, payload) {
		t.Fatal("delivered bytes differ")
	}
}

func TestOnRequestDeclineRejectsSender(t *testing.T) {
	dir := t.TempDir()
	info, _, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir,
		OnRequest: func(RequestInfo) bool { return false }, // decline everything
	})
	defer cancel()

	payload := []byte("should be declined")
	_, err := Send(context.Background(), "nope.txt", int64(len(payload)), false,
		bytes.NewReader(payload), SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port)})
	if err == nil {
		t.Fatal("Send succeeded, want a decline error")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "nope.txt")); statErr == nil {
		t.Fatal("declined file was written to disk")
	}
}

func TestOnRequestReceivesSenderDetails(t *testing.T) {
	dir := t.TempDir()
	var got RequestInfo
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir,
		OnRequest: func(r RequestInfo) bool { got = r; return true },
	})
	defer cancel()

	payload := []byte("hello with details")
	if _, err := Send(context.Background(), "doc.txt", int64(len(payload)), false,
		bytes.NewReader(payload), SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port)}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if out := <-outCh; out.err != nil {
		t.Fatalf("Receive: %v", out.err)
	}
	if got.Name != "doc.txt" || got.Size != int64(len(payload)) {
		t.Fatalf("OnRequest got name=%q size=%d, want doc.txt/%d", got.Name, got.Size, len(payload))
	}
	if got.PeerIP == "" {
		t.Fatal("OnRequest PeerIP empty")
	}
}

func TestBrowseNoReceiversReturnsEmpty(t *testing.T) {
	peers, err := Browse(context.Background(), 300*time.Millisecond)
	if err != nil {
		t.Fatalf("Browse: %v", err)
	}
	// Nothing we started advertises here, so the list is (almost surely) empty;
	// the point is Browse returns cleanly within the timeout without blocking.
	_ = peers
}
