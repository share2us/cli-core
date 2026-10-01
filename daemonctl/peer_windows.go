// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

//go:build windows

package daemonctl

import (
	"errors"
	"net"

	"golang.org/x/sys/windows"
)

func peerProcessID(conn net.Conn) (int, error) {
	// go-winio's pipe connection promotes Fd from its embedded win32File.
	pipe, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return 0, errors.New("control peer is not a named pipe")
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(pipe.Fd()), &pid); err != nil {
		return 0, err
	}
	return int(pid), nil
}
