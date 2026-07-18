package clicore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const CredentialSchemaVersion = 1

type Credential struct {
	SchemaVersion    int    `json:"schema_version,omitempty"`
	APIBase          string `json:"api_base"`
	Token            string `json:"token"`
	Email            string `json:"email"`
	DeviceSessionID  string `json:"device_session_id,omitempty"`
	DevicePublicKey  string `json:"device_public_key,omitempty"`
	DevicePrivateKey string `json:"device_private_key,omitempty"`
}

func CredentialPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "share2us", "credentials.json"), nil
}

func LoadCredential() (Credential, error) {
	path, err := CredentialPath()
	if err != nil {
		return Credential{}, err
	}
	return LoadCredentialAt(path)
}

func LoadCredentialAt(path string) (Credential, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Credential{}, os.ErrNotExist
		}
		return Credential{}, err
	}
	var credential Credential
	if err := json.Unmarshal(raw, &credential); err != nil {
		return Credential{}, fmt.Errorf("parse credentials: %w", err)
	}
	if changed := migrateCredential(&credential); changed && credential.Token != "" {
		_ = SaveCredentialAt(path, credential)
	}
	return credential, nil
}

func SaveCredential(credential Credential) error {
	path, err := CredentialPath()
	if err != nil {
		return err
	}
	return SaveCredentialAt(path, credential)
}

func SaveCredentialAt(path string, credential Credential) error {
	if credential.APIBase == "" {
		credential.APIBase = DefaultAPIBase
	}
	credential.SchemaVersion = CredentialSchemaVersion
	raw, err := json.MarshalIndent(credential, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func migrateCredential(credential *Credential) bool {
	if credential == nil {
		return false
	}
	if credential.SchemaVersion > CredentialSchemaVersion {
		return false
	}
	changed := false
	switch credential.SchemaVersion {
	case 0:
		credential.SchemaVersion = 1
		changed = true
		fallthrough
	case 1:
	}
	return changed
}

func DeleteCredential() error {
	path, err := CredentialPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
