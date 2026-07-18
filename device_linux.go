package clicore

import (
	"errors"
	"os"
	"strings"
)

func stableMachineID() (string, error) {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if id := strings.TrimSpace(string(raw)); id != "" {
			return id, nil
		}
	}
	return "", errors.New("machine id not found")
}
