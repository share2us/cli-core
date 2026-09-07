// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

//go:build !windows

package daemonctl

import (
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	clicore "github.com/share2us/cli-core"
)

// controlEndpoint is the per-user unix socket path.
func controlEndpoint() (string, error) {
	return clicore.DaemonSocketPath()
}

// bindControl binds the unix socket (the single-instance lock). If the bind
// fails because the socket file already exists, it connects to it: a successful
// connect means a live daemon owns it (ErrAlreadyRunning); a refused connect
// means a stale socket from a crash, which is removed and rebound. release
// removes the socket file on Close.
func bindControl(sock string) (net.Listener, func(), error) {
	ln, err := net.Listen("unix", sock)
	if err != nil && errors.Is(err, syscall.EADDRINUSE) {
		if c, derr := net.DialTimeout("unix", sock, dialTimeout); derr == nil {
			_ = c.Close()
			return nil, nil, ErrAlreadyRunning
		}
		_ = os.Remove(sock)
		ln, err = net.Listen("unix", sock)
	}
	if err != nil {
		return nil, nil, err
	}
	return ln, func() { _ = os.Remove(sock) }, nil
}

func dialControl(sock string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", sock, timeout)
}
