// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"errors"
	"github.com/share2us/cli-core/internal/proc"
	"strings"
)

func stableMachineID() (string, error) {
	out, err := proc.Hidden("reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	for i, field := range fields {
		if strings.EqualFold(field, "MachineGuid") && i+2 < len(fields) {
			id := strings.TrimSpace(fields[i+2])
			if id != "" {
				return id, nil
			}
		}
	}
	return "", errors.New("machine id not found")
}
