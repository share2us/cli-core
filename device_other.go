// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

//go:build !linux && !darwin && !windows

package clicore

import "errors"

func stableMachineID() (string, error) {
	return "", errors.New("machine id not available")
}
