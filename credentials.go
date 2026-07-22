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

// CredentialPath is where the CLI stores its saved login. It mirrors ConfigPath
// (os.UserConfigDir) so the token and config.json live together: ~/.config/share2us
// on Linux/macOS (honoring XDG_CONFIG_HOME) and %AppData%\Roaming\share2us on
// Windows. Before 2026-07 this used XDG/HOME directly, which on Windows put the
// token under %USERPROFILE%\.config instead — see legacyCredentialPath.
func CredentialPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "share2us", "credentials.json"), nil
}

// legacyCredentialPath is the pre-2026-07 location: XDG_CONFIG_HOME, else
// ~/.config. Identical to CredentialPath on Linux/macOS; on Windows it is
// %USERPROFILE%\.config (not %AppData%). Read as a fallback so an existing login
// survives the move to os.UserConfigDir.
func legacyCredentialPath() (string, error) {
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
	cred, err := LoadCredentialAt(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return cred, err
	}
	// New path absent: fall back to the legacy location (on Windows the token
	// moved from %USERPROFILE%\.config to %AppData%). On Linux/macOS the two paths
	// are identical, so there is nothing to fall back to.
	legacy, lerr := legacyCredentialPath()
	if lerr != nil || legacy == path {
		return cred, err
	}
	legacyCred, lerr := LoadCredentialAt(legacy)
	if lerr != nil {
		return cred, err // report the original not-found, not the legacy miss
	}
	_ = SaveCredentialAt(path, legacyCred) // best-effort migrate forward
	return legacyCred, nil
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
