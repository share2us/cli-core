// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

//go:build !windows

package daemonctl

import (
	"errors"
	"net"
	"syscall"
	"time"
)

// listenSocket binds a unix-domain stream socket. Binding is the single-instance
// lock (a second bind fails with EADDRINUSE).
func listenSocket(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}

func dialSocket(path string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", path, timeout)
}

// isAddrInUse distinguishes a live daemon from a stale socket file to clear.
func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}
