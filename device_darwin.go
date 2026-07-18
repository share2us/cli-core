package clicore

import (
	"errors"
	"os/exec"
	"strings"
)

func stableMachineID() (string, error) {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		_, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		id := strings.Trim(strings.TrimSpace(value), `"`)
		if id != "" {
			return id, nil
		}
	}
	return "", errors.New("machine id not found")
}
