package clicore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyCredentialLoadsAndUpgrades(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(`{"api_base":"https://api.x","token":"s2s_legacy","email":"a@b"}`), 0o600); err != nil {
		t.Fatalf("write legacy credential: %v", err)
	}

	credential, err := LoadCredentialAt(path)
	if err != nil {
		t.Fatalf("LoadCredentialAt() error = %v", err)
	}
	if credential.Token != "s2s_legacy" || credential.APIBase != "https://api.x" || credential.Email != "a@b" {
		t.Fatalf("credential = %+v", credential)
	}
	if credential.SchemaVersion != CredentialSchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", credential.SchemaVersion, CredentialSchemaVersion)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migrated credential: %v", err)
	}
	var onDisk Credential
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("decode migrated credential: %v", err)
	}
	if onDisk.SchemaVersion != CredentialSchemaVersion || onDisk.Token != "s2s_legacy" {
		t.Fatalf("on disk credential = %+v", onDisk)
	}
}

func TestCredentialUnknownFutureFieldIgnored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(`{"token":"s2s_x","some_future_field":"z","schema_version":1}`), 0o600); err != nil {
		t.Fatalf("write credential: %v", err)
	}

	credential, err := LoadCredentialAt(path)
	if err != nil {
		t.Fatalf("LoadCredentialAt() error = %v", err)
	}
	if credential.Token != "s2s_x" {
		t.Fatalf("Token = %q, want s2s_x", credential.Token)
	}
}

func TestCredentialNewerSchemaTolerated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(`{"token":"s2s_x","schema_version":999}`), 0o600); err != nil {
		t.Fatalf("write credential: %v", err)
	}

	credential, err := LoadCredentialAt(path)
	if err != nil {
		t.Fatalf("LoadCredentialAt() error = %v", err)
	}
	if credential.Token != "s2s_x" || credential.SchemaVersion != 999 {
		t.Fatalf("credential = %+v", credential)
	}
}

func TestCredentialSaveLoadRoundTripSetsSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "share2us", "credentials.json")
	want := Credential{APIBase: "https://api.example.test", Token: "s2s_secret", Email: "user@example.test"}
	if err := SaveCredentialAt(path, want); err != nil {
		t.Fatalf("SaveCredentialAt() error = %v", err)
	}

	got, err := LoadCredentialAt(path)
	if err != nil {
		t.Fatalf("LoadCredentialAt() error = %v", err)
	}
	if got.SchemaVersion != CredentialSchemaVersion || got.APIBase != want.APIBase || got.Token != want.Token || got.Email != want.Email {
		t.Fatalf("credential = %+v, want api=%q token=%q email=%q schema=%d", got, want.APIBase, want.Token, want.Email, CredentialSchemaVersion)
	}
}

func TestCredentialCorruptJSONStillErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(`{not json`), 0o600); err != nil {
		t.Fatalf("write corrupt credential: %v", err)
	}

	_, err := LoadCredentialAt(path)
	if err == nil || !strings.Contains(err.Error(), "parse credentials") {
		t.Fatalf("LoadCredentialAt() error = %v, want parse credentials error", err)
	}
}
