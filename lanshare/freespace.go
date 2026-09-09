// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import "fmt"

// ensureFreeSpace refuses a transfer that plainly cannot fit, so a peer cannot
// fill the disk and take the machine down with it (§AJ #32). It is a courtesy
// check, not a guarantee: the space can still be consumed by something else
// while the transfer runs, which is why the receive loop also holds the stream
// to the declared size.
//
// A platform where the free space cannot be read returns nil: refusing every
// transfer because a syscall is unavailable would be worse than the risk.
func ensureFreeSpace(dir string, need int64) error {
	if need <= 0 {
		return nil
	}
	free, ok := freeSpace(dir)
	if !ok {
		return nil
	}
	// Leave a margin so a transfer never fills the last block of the disk.
	const margin = 64 << 20
	if free < uint64(need)+margin {
		return fmt.Errorf("lanshare: not enough free space for %d bytes (%d available)", need, free)
	}
	return nil
}
