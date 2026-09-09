// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import (
	"testing"
	"time"
)

// §AJ #31: the transfer deadline was cleared outright, so a peer could drip one
// frame every 59 seconds (inside the per-frame read deadline) and hold the
// receiver's connection indefinitely.
func TestTransferDeadlineIsGenerousButFinite(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)

	// A small transfer still gets the full grace period.
	if got := transferDeadline(now, 1024).Sub(now); got < transferGrace {
		t.Fatalf("small transfer allowed %s, less than the %s floor", got, transferGrace)
	}
	// A 1 GiB transfer gets over 18 hours' worth of slack at 16 KiB/s, clamped.
	big := transferDeadline(now, 1<<30).Sub(now)
	if big <= transferGrace {
		t.Fatalf("a 1 GiB transfer got no more time than a tiny one (%s)", big)
	}
	if big > transferMaxDuration {
		t.Fatalf("deadline %s exceeds the cap %s", big, transferMaxDuration)
	}
	// Nothing is unbounded.
	huge := transferDeadline(now, 1<<62).Sub(now)
	if huge != transferMaxDuration {
		t.Fatalf("an absurd declared size gave %s, want the %s cap", huge, transferMaxDuration)
	}
	// A real 100 MB transfer over a slow 1 MB/s link takes 100s; the deadline
	// must be far beyond that.
	if d := transferDeadline(now, 100<<20).Sub(now); d < 15*time.Minute {
		t.Fatalf("a 100 MB transfer only got %s", d)
	}
}
