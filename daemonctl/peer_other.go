// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

//go:build !linux && !darwin && !windows

package daemonctl

import (
	"errors"
	"net"
)

func peerProcessID(net.Conn) (int, error) {
	return 0, errors.New("control peer PID unavailable on this platform")
}
