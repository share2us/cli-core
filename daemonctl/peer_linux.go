// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

//go:build linux

package daemonctl

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func peerProcessID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("control peer is not a Unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid int
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		var cred *unix.Ucred
		cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if sockErr == nil {
			pid = int(cred.Pid)
		}
	})
	if err != nil {
		return 0, err
	}
	return pid, sockErr
}
