//go:build !linux && !darwin && !windows

package clicore

import "errors"

func stableMachineID() (string, error) {
	return "", errors.New("machine id not available")
}
