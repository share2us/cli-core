// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

// OnTransferStart hands back a per-transfer cancel. cancel(true) is a pause: it
// stops this transfer but leaves the partial so a resend resumes it. cancel(false)
// is a cancel: it discards the partial so nothing is left behind.
func TestOnTransferStartCancelKeepsOrDiscardsPartial(t *testing.T) {
	for _, tc := range []struct {
		name string
		keep bool
	}{
		{"pause keeps the partial for resume", true},
		{"cancel discards the partial", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			body := bytes.Repeat([]byte("abcdefghij"), 40000) // 400 KiB, many frames
			size := int64(len(body))

			var mu sync.Mutex
			var cancelFn func(bool)
			cancelled := false
			info, outCh, stop := startReceiver(t, ReceiveOptions{
				Bind: "127.0.0.1", NoPassword: true, DestDir: dir, Overwrite: true,
				OnTransferStart: func(_ RequestInfo, cancel func(bool)) {
					mu.Lock()
					cancelFn = cancel
					mu.Unlock()
				},
				OnProgress: func(received, total int64) {
					mu.Lock()
					defer mu.Unlock()
					if !cancelled && cancelFn != nil && received > 0 && received < total {
						cancelled = true
						cancelFn(tc.keep)
					}
				},
			})
			addr := "127.0.0.1:" + strconv.Itoa(info.Port)
			if _, err := Send(context.Background(), "big.bin", size, false, bytes.NewReader(body),
				SendOptions{Dest: addr, Resume: true}); err == nil {
				t.Fatal("send should have failed: the transfer was cancelled mid-stream")
			}
			stop()
			<-outCh

			partials, _ := filepath.Glob(filepath.Join(dir, ".s2u-partial-*"))
			if !tc.keep {
				if len(partials) != 0 {
					t.Fatalf("cancel: expected no partial left behind, got %v", partials)
				}
				return
			}
			if len(partials) != 1 {
				t.Fatalf("pause: expected exactly one partial kept, got %v", partials)
			}
			// A resend resumes from the kept partial and completes correctly.
			info2, outCh2, stop2 := startReceiver(t, ReceiveOptions{
				Bind: "127.0.0.1", NoPassword: true, DestDir: dir, Overwrite: true,
			})
			defer func() { stop2(); <-outCh2 }()
			if _, err := Send(context.Background(), "big.bin", size, false, bytes.NewReader(body),
				SendOptions{Dest: "127.0.0.1:" + strconv.Itoa(info2.Port), Resume: true}); err != nil {
				t.Fatalf("resume after pause failed: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(dir, "big.bin"))
			if err != nil || !bytes.Equal(got, body) {
				t.Fatalf("resumed file is wrong: err=%v len=%d want %d", err, len(got), size)
			}
		})
	}
}
