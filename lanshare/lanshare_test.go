package lanshare

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
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

func TestReceiveRejectsMaliciousFilenames(t *testing.T) {
	// Hard-rejected: illegal characters, reserved device names, extension spoofing.
	rejected := []string{
		"..\\escape.txt",      // backslash separator (illegal char on the receiver)
		"report.pdf:evil.exe", // NTFS alternate data stream marker
		"nul",                 // Windows reserved device name
		"COM1.txt",            // reserved device name with an extension
		"photo\u202egnp.exe",  // RTLO extension spoof
	}
	for _, name := range rejected {
		dir := t.TempDir()
		info, _, cancel := startReceiver(t, ReceiveOptions{Bind: "127.0.0.1", NoPassword: true, DestDir: dir})
		_, err := Send(context.Background(), name, 1, false, bytes.NewReader([]byte("x")),
			SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port)})
		cancel()
		if err == nil {
			t.Errorf("Send(name=%q) succeeded; expected rejection", name)
		}
	}

	// Path traversal in the basename is neutralized (written as the basename
	// inside the dest dir), not escaping the directory.
	dir := t.TempDir()
	info, outCh, cancel := startReceiver(t, ReceiveOptions{Bind: "127.0.0.1", NoPassword: true, DestDir: dir})
	if _, err := Send(context.Background(), "../escape.txt", 1, false, bytes.NewReader([]byte("x")),
		SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port)}); err != nil {
		cancel()
		t.Fatalf("traversal-basename send failed: %v", err)
	}
	<-outCh
	cancel()
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(dir), "escape.txt")); statErr == nil {
		t.Error("traversal escaped the destination directory")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "escape.txt")); statErr != nil {
		t.Error("traversal basename was not written safely inside the dest dir")
	}
}

func TestVerifyCode(t *testing.T) {
	c := VerifyCode("aabbccdd")
	if len(c) != 7 { // "NNN NNN"
		t.Fatalf("code %q length = %d, want 7", c, len(c))
	}
	if VerifyCode("AA:BB:CC:DD") != c {
		t.Fatal("code changed under fingerprint separators/case (normalization broken)")
	}
	if VerifyCode("aabbccdd") == VerifyCode("11223344") {
		t.Fatal("distinct fingerprints produced the same code")
	}
	if VerifyCode("") != "" {
		t.Fatal("empty fingerprint should yield empty code")
	}
}

func TestServeLoopReceivesMultiple(t *testing.T) {
	dir := t.TempDir()
	recv := make(chan string, 8)
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir, Overwrite: true,
		Loop:       true,
		OnRequest:  func(RequestInfo) bool { return true },
		OnReceived: func(r ReceiveResult) { recv <- r.Name },
	})
	addr := "127.0.0.1:" + strconv.Itoa(info.Port)
	for i := 0; i < 3; i++ {
		if _, err := Send(context.Background(), "f"+strconv.Itoa(i)+".txt", 2, false,
			bytes.NewReader([]byte("hi")), SendOptions{Dest: addr}); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	for i := 0; i < 3; i++ {
		select {
		case <-recv:
		case <-time.After(3 * time.Second):
			t.Fatalf("only received %d of 3 transfers in serve/loop mode", i)
		}
	}
	cancel()
	<-outCh
}

func TestSenderIdentityRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	var gotKey []byte
	var gotName string
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir,
		OnRequest: func(r RequestInfo) bool { gotKey = r.SenderKey; gotName = r.SenderName; return true },
	})
	defer cancel()

	if _, err := Send(context.Background(), "id.txt", 2, false, bytes.NewReader([]byte("hi")),
		SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port), Identity: priv, SenderName: "Test-PC"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if out := <-outCh; out.err != nil {
		t.Fatalf("Receive: %v", out.err)
	}
	if !bytes.Equal(gotKey, pub) {
		t.Fatal("receiver did not see the sender's verified public key")
	}
	if gotName != "Test-PC" {
		t.Fatalf("sender name = %q, want Test-PC", gotName)
	}
	// Fingerprint is stable + nonempty.
	if IdentityFingerprint(pub) == "" || IdentityFingerprint(pub) != IdentityFingerprint(pub) {
		t.Fatal("bad fingerprint")
	}
}

func TestForgedSenderIdentityRejected(t *testing.T) {
	// A sender that presents someone else's pubkey but can't sign for it must be
	// rejected (the signature won't verify against the claimed key). Craft the
	// hello directly rather than via Send, which always signs honestly.
	victimPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	info, _, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir,
		OnRequest: func(RequestInfo) bool { return true },
	})
	defer cancel()

	raw, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(info.Port))
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, clientTLSConfig(info.Fingerprint))
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	ekm, err := exportKeyingMaterial(conn)
	if err != nil {
		t.Fatal(err)
	}
	// Claim the victim's public key, sign with the attacker's key.
	sig := ed25519.Sign(attackerPriv, identityMessage(ekm))
	h := hello{Version: protocolVersion, Name: "forge.txt", Size: 2, IdentityPub: victimPub, IdentitySig: sig}
	if err := writeJSON(conn, msgHello, h); err != nil {
		t.Fatal(err)
	}
	var acc accept
	if err := readControl(conn, msgAccept, &acc); err == nil && acc.OK {
		t.Fatal("forged identity was accepted; expected rejection")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "forge.txt")); statErr == nil {
		t.Fatal("forged-identity file was written")
	}
}

func TestAnonymousSenderStillWorks(t *testing.T) {
	dir := t.TempDir()
	var key []byte
	present := false
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir,
		OnRequest: func(r RequestInfo) bool { key = r.SenderKey; present = true; return true },
	})
	defer cancel()
	if _, err := Send(context.Background(), "anon.txt", 2, false, bytes.NewReader([]byte("hi")),
		SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port)}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if out := <-outCh; out.err != nil {
		t.Fatalf("Receive: %v", out.err)
	}
	if !present || key != nil {
		t.Fatal("anonymous sender should reach OnRequest with a nil SenderKey")
	}
}

func startBroadcaster(t *testing.T, opts BroadcastOptions) (ListenInfo, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	infoCh := make(chan ListenInfo, 1)
	user := opts.OnListen
	opts.OnListen = func(info ListenInfo) {
		if user != nil {
			user(info)
		}
		infoCh <- info
	}
	go func() { _ = Broadcast(ctx, opts) }()
	select {
	case info := <-infoCh:
		return info, cancel
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("broadcaster did not start listening")
		return ListenInfo{}, cancel
	}
}

func TestBroadcastDownloadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "offer.bin")
	payload := randomBytes(t, 300*1024)
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	info, cancel := startBroadcaster(t, BroadcastOptions{Bind: "127.0.0.1", Path: src, Access: AccessAll})
	defer cancel()

	destDir := t.TempDir()
	res, err := Download(context.Background(), DownloadOptions{
		Dest: "127.0.0.1:" + strconv.Itoa(info.Port), PinFingerprint: info.Fingerprint,
		Name: "offer.bin", Size: int64(len(payload)), DestDir: destDir,
	})
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(destDir, "offer.bin"))
	if !bytes.Equal(got, payload) {
		t.Fatal("downloaded bytes differ from source")
	}
	if res.SHA256 != sha256Hex(payload) {
		t.Fatal("sha mismatch")
	}
}

func TestBroadcastTrustedAccess(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "f.bin")
	os.WriteFile(src, []byte("secret payload"), 0o600)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	trustedFP := IdentityFingerprint(pub)
	info, cancel := startBroadcaster(t, BroadcastOptions{
		Bind: "127.0.0.1", Path: src, Access: AccessTrusted,
		IsTrusted: func(fp string) bool { return fp == trustedFP },
	})
	defer cancel()
	dest := "127.0.0.1:" + strconv.Itoa(info.Port)

	if _, err := Download(context.Background(), DownloadOptions{Dest: dest, PinFingerprint: info.Fingerprint, Name: "f.bin", Size: 14, DestDir: t.TempDir()}); err == nil {
		t.Fatal("anonymous downloader was allowed on a trusted-only broadcast")
	}
	if _, err := Download(context.Background(), DownloadOptions{Dest: dest, PinFingerprint: info.Fingerprint, Name: "f.bin", Size: 14, DestDir: t.TempDir(), Identity: priv}); err != nil {
		t.Fatalf("trusted downloader was rejected: %v", err)
	}
}

func TestDownloadResume(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "big.bin")
	payload := randomBytes(t, 500*1024) // ~8 chunks
	os.WriteFile(src, payload, 0o600)
	info, cancel := startBroadcaster(t, BroadcastOptions{Bind: "127.0.0.1", Path: src, Access: AccessAll})
	defer cancel()
	dest := "127.0.0.1:" + strconv.Itoa(info.Port)
	destDir := t.TempDir()

	// Interrupt partway through the first attempt.
	ctx1, cancel1 := context.WithCancel(context.Background())
	_, err := Download(ctx1, DownloadOptions{
		Dest: dest, PinFingerprint: info.Fingerprint, Name: "big.bin", Size: int64(len(payload)), DestDir: destDir,
		OnProgress: func(recv, total int64) {
			if recv > total/2 {
				cancel1()
			}
		},
	})
	cancel1()
	if err == nil {
		t.Fatal("expected the first download to be interrupted")
	}

	// Resume — should complete and match.
	res, err := Download(context.Background(), DownloadOptions{
		Dest: dest, PinFingerprint: info.Fingerprint, Name: "big.bin", Size: int64(len(payload)), DestDir: destDir,
	})
	if err != nil {
		t.Fatalf("resume download failed: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(destDir, "big.bin"))
	if !bytes.Equal(got, payload) {
		t.Fatal("resumed file differs from source")
	}
	if res.SHA256 != sha256Hex(payload) {
		t.Fatal("resumed sha mismatch")
	}
}

func TestBroadcastProvesIdentityToDownloader(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "id.bin")
	os.WriteFile(src, []byte("hello from a known device"), 0o600)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	info, cancel := startBroadcaster(t, BroadcastOptions{Bind: "127.0.0.1", Path: src, Access: AccessAll, Identity: priv})
	defer cancel()
	res, err := Download(context.Background(), DownloadOptions{
		Dest: "127.0.0.1:" + strconv.Itoa(info.Port), PinFingerprint: info.Fingerprint,
		Name: "id.bin", Size: 25, DestDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if !bytes.Equal(res.SenderKey, pub) {
		t.Fatal("downloader did not receive the broadcaster's verified identity key")
	}
	if IdentityFingerprint(res.SenderKey) == "" {
		t.Fatal("empty broadcaster fingerprint")
	}
}

// --- push-path resume ---

// haltingReader simulates a transfer dying partway through. It must survive the
// sender's up-front hashing pass intact and fail only once streaming starts,
// which is why it counts seeks: hashSeekable seeks twice (once to rewind before
// hashing, once after), so anything from the second seek on is the real send.
type haltingReader struct {
	data  []byte
	pos   int
	seeks int
}

func (r *haltingReader) Read(p []byte) (int, error) {
	if r.seeks >= 2 {
		// Streaming phase: hand over half the file, then fail. This must be a
		// non-EOF error, since streamBodyFrom treats io.EOF as a clean finish.
		half := len(r.data) / 2
		if r.pos >= half {
			return 0, errors.New("simulated network failure")
		}
		n := copy(p, r.data[r.pos:half])
		r.pos += n
		return n, nil
	}
	// Hashing phase: read the whole thing and end with a clean EOF, or
	// hashSeekable fails and the send never reaches the wire at all.
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *haltingReader) Seek(offset int64, whence int) (int64, error) {
	if whence != io.SeekStart {
		return 0, errors.New("unsupported whence")
	}
	r.pos = int(offset)
	r.seeks++
	return offset, nil
}

func TestPushResumeContinuesFromPartial(t *testing.T) {
	dir := t.TempDir()
	body := bytes.Repeat([]byte("abcdefghij"), 4096) // 40 KiB
	size := int64(len(body))

	// First attempt dies partway through, leaving a partial behind.
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir, Overwrite: true,
	})
	addr := "127.0.0.1:" + strconv.Itoa(info.Port)
	halting := &haltingReader{data: body}
	if _, err := Send(context.Background(), "big.bin", size, false, halting,
		SendOptions{Dest: addr, Resume: true}); err == nil {
		t.Fatal("first attempt should have failed mid-stream")
	}
	cancel()
	<-outCh

	partials, _ := filepath.Glob(filepath.Join(dir, ".s2u-partial-*"))
	if len(partials) != 1 {
		t.Fatalf("expected exactly one partial to survive, got %v", partials)
	}
	kept, _ := os.Stat(partials[0])
	if kept.Size() == 0 || kept.Size() >= size {
		t.Fatalf("partial size = %d, want a strict prefix of %d", kept.Size(), size)
	}

	// Second attempt resumes and completes.
	info2, outCh2, cancel2 := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir, Overwrite: true,
	})
	defer func() { cancel2(); <-outCh2 }()
	addr2 := "127.0.0.1:" + strconv.Itoa(info2.Port)

	var firstProgress int64 = -1
	_, err := Send(context.Background(), "big.bin", size, false, bytes.NewReader(body), SendOptions{
		Dest:   addr2,
		Resume: true,
		OnProgress: func(sent, _ int64) {
			if firstProgress < 0 {
				firstProgress = sent
			}
		},
	})
	if err != nil {
		t.Fatalf("resumed send failed: %v", err)
	}
	if firstProgress <= 0 {
		t.Fatalf("resume did not skip ahead: first progress report was %d", firstProgress)
	}

	got, err := os.ReadFile(filepath.Join(dir, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("resumed file is corrupt: got %d bytes, want %d", len(got), len(body))
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".s2u-partial-*")); len(left) != 0 {
		t.Fatalf("partial not cleaned up after success: %v", left)
	}
}

func TestPushWithoutResumeLeavesNoPartialAndStillWorks(t *testing.T) {
	// A sender that does not advertise resume must behave exactly as before: no
	// resumable partial is created, and an interrupted transfer leaves nothing.
	dir := t.TempDir()
	body := bytes.Repeat([]byte("x"), 20000)

	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir, Overwrite: true,
	})
	addr := "127.0.0.1:" + strconv.Itoa(info.Port)
	if _, err := Send(context.Background(), "plain.bin", int64(len(body)), false,
		bytes.NewReader(body), SendOptions{Dest: addr}); err != nil {
		t.Fatalf("plain send failed: %v", err)
	}
	cancel()
	<-outCh

	got, err := os.ReadFile(filepath.Join(dir, "plain.bin"))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("plain send did not land correctly: err=%v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".s2u-partial-*")); len(left) != 0 {
		t.Fatalf("non-resume send left a partial: %v", left)
	}
}

func TestPushResumePartialIsKeyedByContent(t *testing.T) {
	// Two different files sharing a name AND size must not share a partial —
	// that is what stops a resume splicing one file onto another.
	a := partialName(strings.Repeat("a", 64), "same.bin", 1024)
	b := partialName(strings.Repeat("b", 64), "same.bin", 1024)
	if a == b {
		t.Fatalf("partials collided across different content digests: %s", a)
	}
}

// mutatingReader hashes as one file but streams a different one, standing in for
// a sender whose bytes do not match the digest it declared.
type mutatingReader struct {
	honest []byte
	lie    []byte
	pos    int
	seeks  int
}

func (r *mutatingReader) body() []byte {
	if r.seeks >= 2 {
		return r.lie
	}
	return r.honest
}

func (r *mutatingReader) Read(p []byte) (int, error) {
	b := r.body()
	if r.pos >= len(b) {
		return 0, io.EOF
	}
	n := copy(p, b[r.pos:])
	r.pos += n
	return n, nil
}

func (r *mutatingReader) Seek(offset int64, whence int) (int64, error) {
	r.pos = int(offset)
	r.seeks++
	return offset, nil
}

func TestPushResumeRefusesToPlaceMismatchedContent(t *testing.T) {
	dir := t.TempDir()
	honest := bytes.Repeat([]byte("A"), 4096)
	lie := bytes.Repeat([]byte("B"), 4096)

	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir, Overwrite: true,
	})
	defer func() { cancel(); <-outCh }()

	_, err := Send(context.Background(), "evil.bin", int64(len(honest)), false,
		&mutatingReader{honest: honest, lie: lie},
		SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port), Resume: true})
	if err == nil {
		t.Fatal("a digest mismatch must fail the transfer")
	}

	// The receiver must not have written the destination file, and must not have
	// kept a partial that a later resume would build on.
	if _, statErr := os.Stat(filepath.Join(dir, "evil.bin")); statErr == nil {
		t.Fatal("receiver placed a file whose content did not match the declared digest")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".s2u-partial-*")); len(left) != 0 {
		t.Fatalf("receiver kept an untrustworthy partial: %v", left)
	}
}
