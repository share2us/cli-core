// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import "time"

const (
	// transferGrace is the floor: even a zero-byte transfer gets this long, and
	// it absorbs a slow disk or a paused laptop.
	transferGrace = 10 * time.Minute
	// transferMinBytesPerSecond is the slowest a transfer may run before it is
	// treated as stalled. Well under any real LAN or Wi-Fi link, so a genuine
	// transfer is never cut off; far above one frame a minute.
	transferMinBytesPerSecond = 16 * 1024
	// transferMaxDuration caps the whole thing however large the declared size.
	transferMaxDuration = 12 * time.Hour
)

// transferDeadline returns when a transfer of size bytes, started at now, must
// be finished by (§AJ #31).
func transferDeadline(now time.Time, size int64) time.Time {
	d := transferGrace
	if size > 0 {
		// Clamp the seconds BEFORE converting: a nonsense declared size would
		// otherwise overflow time.Duration and produce a deadline in the past.
		seconds := size / transferMinBytesPerSecond
		if max := int64(transferMaxDuration / time.Second); seconds > max {
			seconds = max
		}
		d += time.Duration(seconds) * time.Second
	}
	if d > transferMaxDuration {
		d = transferMaxDuration
	}
	return now.Add(d)
}
