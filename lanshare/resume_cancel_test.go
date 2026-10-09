// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// slowSeeker is a seekable reader whose every Read sleeps, so hashing it takes a
// controllable, measurable time — used to prove a cancel during the pre-send hash
// is honored promptly rather than after the whole file is read.
type slowSeeker struct {
	data  []byte
	pos   int
	delay time.Duration
}

func (s *slowSeeker) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	time.Sleep(s.delay)
	n := copy(p, s.data[s.pos:])
	s.pos += n
	return n, nil
}

func (s *slowSeeker) Seek(off int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		s.pos = int(off)
	case io.SeekCurrent:
		s.pos += int(off)
	case io.SeekEnd:
		s.pos = len(s.data) + int(off)
	}
	return int64(s.pos), nil
}

// A pause/cancel issued while the sender is computing the pre-send SHA of a large
// file must take effect promptly, not after the entire file has been read. This is
// the reported "second pause/cancel kept going" on a multi-GB transfer.
func TestSendCancelDuringPreSendHash(t *testing.T) {
	dir := t.TempDir()
	info, outCh, stop := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir, Overwrite: true,
	})
	defer func() { stop(); <-outCh }()

	// 10 chunks * 400ms = ~4s to hash if the read ignored cancellation.
	size := int64(10 << 20)
	sr := &slowSeeker{data: bytes.Repeat([]byte("x"), int(size)), delay: 400 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }() // cancel mid-hash

	start := time.Now()
	_, err := Send(ctx, "big.bin", size, false, sr, SendOptions{
		Dest: "127.0.0.1:" + strconv.Itoa(info.Port), Resume: true,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("cancel during the pre-send hash should fail the send")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("cancel during hash was not honored promptly: took %v (would be ~4s if the whole file is read first)", elapsed)
	}
}

// A send must honor context cancellation BOTH on the first attempt and on a resume
// (the GUI's pause = cancel the send ctx; resume = re-send; pause again = cancel
// again). This reproduces the report "second pause/cancel kept going".
func TestSendCancelThenResumeCancelAgain(t *testing.T) {
	dir := t.TempDir()
	body := bytes.Repeat([]byte("abcdefghij"), 300000) // 3 MB, many frames
	size := int64(len(body))

	// sendCancelEarly cancels on the FIRST progress tick, so each attempt leaves a
	// small partial and the next resume still has most of the file left to send.
	sendCancelEarly := func() error {
		info, outCh, stop := startReceiver(t, ReceiveOptions{
			Bind: "127.0.0.1", NoPassword: true, DestDir: dir, Overwrite: true,
		})
		defer func() { stop(); <-outCh }()
		ctx, cancel := context.WithCancel(context.Background())
		done := false
		_, err := Send(ctx, "big.bin", size, false, bytes.NewReader(body), SendOptions{
			Dest:   "127.0.0.1:" + strconv.Itoa(info.Port),
			Resume: true,
			OnProgress: func(sent, total int64) {
				if !done && sent > 0 && sent < total {
					done = true
					cancel()
				}
			},
		})
		return err
	}

	// First pause: cancel mid-stream, partial kept.
	if err := sendCancelEarly(); err == nil {
		t.Fatal("first send should have been cancelled mid-stream")
	}
	if p, _ := filepath.Glob(filepath.Join(dir, ".s2u-partial-*")); len(p) != 1 {
		t.Fatalf("first cancel should keep exactly one partial, got %v", p)
	}

	// Resume, then pause AGAIN mid-stream: this must also stop.
	if err := sendCancelEarly(); err == nil {
		t.Fatal("resumed send should ALSO cancel mid-stream, not run to completion")
	}
}
