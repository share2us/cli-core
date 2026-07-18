package clicore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

type DeviceMetadata struct {
	DeviceName string
	MachineID  string
	OS         string
	Arch       string
	Hostname   string
}

func DetectDeviceMetadata(deviceName string) (DeviceMetadata, error) {
	hostname, _ := os.Hostname()
	deviceName = strings.TrimSpace(deviceName)
	if deviceName == "" {
		deviceName = strings.TrimSpace(hostname)
	}
	if deviceName == "" {
		deviceName = "Share2Us CLI"
	}

	rawID, err := stableMachineID()
	if err != nil || rawID == "" {
		rawID, err = fallbackMachineID()
		if err != nil {
			return DeviceMetadata{}, err
		}
	}
	sum := sha256.Sum256([]byte(rawID))
	return DeviceMetadata{
		DeviceName: deviceName,
		MachineID:  hex.EncodeToString(sum[:]),
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Hostname:   hostname,
	}, nil
}

func fallbackMachineID() (string, error) {
	config, err := LoadConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if strings.TrimSpace(config.MachineID) != "" {
		return strings.TrimSpace(config.MachineID), nil
	}
	generated, err := randomUUID()
	if err != nil {
		return "", err
	}
	config.MachineID = generated
	if err := SaveConfig(config); err != nil {
		return "", err
	}
	return generated, nil
}

func randomUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate machine id: %w", err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[0:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32]), nil
}
