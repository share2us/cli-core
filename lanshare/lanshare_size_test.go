package lanshare

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A sender that declares a tiny size but streams far more (the disk-fill attack)
// must be aborted, not written to disk indefinitely.
func TestReceiveRejectsOverDeclaredStream(t *testing.T) {
	dir := t.TempDir()
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir,
	})
	defer cancel()

	body := make([]byte, 2<<20) // 2 MiB streamed against a declared 5 bytes
	_, err := Send(context.Background(), "evil.bin", 5, false, bytes.NewReader(body),
		SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port)})
	if err == nil {
		t.Fatal("Send of an over-declared stream unexpectedly succeeded")
	}

	select {
	case out := <-outCh:
		if out.err == nil {
			t.Fatalf("Receive returned success for an over-declared stream: %+v", out.res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receiver did not return after aborting the over-declared stream")
	}

	// Nothing should have been finalized into the destination directory.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".s2u-partial-") {
			t.Errorf("unexpected finalized file left behind: %s", e.Name())
		}
	}
}

// A hello that declares an absurd size must be refused before any data is
// streamed.
func TestReceiveRejectsOversizeDeclared(t *testing.T) {
	dir := t.TempDir()
	info, _, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir,
	})
	defer cancel()

	_, err := Send(context.Background(), "big.bin", maxTransferBytes+1, false, bytes.NewReader([]byte("x")),
		SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port)})
	if err == nil {
		t.Fatal("Send with an oversize declared size unexpectedly succeeded")
	}
}

// A sender that ends the stream short of its declared size must fail, not land a
// partial file as if complete.
func TestReceiveRejectsUnderDeclaredStream(t *testing.T) {
	dir := t.TempDir()
	info, outCh, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir,
	})
	defer cancel()

	// Declare 1000 bytes but stream only 10 before EOF.
	_, err := Send(context.Background(), "short.bin", 1000, false, bytes.NewReader([]byte("0123456789")),
		SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info.Port)})
	if err == nil {
		t.Fatal("Send of an under-declared stream unexpectedly succeeded")
	}

	select {
	case out := <-outCh:
		if out.err == nil {
			t.Fatalf("Receive accepted an incomplete transfer: %+v", out.res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receiver did not return after the short stream")
	}
}
