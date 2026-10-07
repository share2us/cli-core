package clicore

import (
	"os"
	"testing"
)

func TestPrepareLoginSigningKeyPersistsAndReuses(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	first, err := PrepareLoginSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := LoadCredential()
	if err != nil {
		t.Fatal(err)
	}
	if first.PublicKey == "" || cred.DeviceSigningPublicKey != first.PublicKey || cred.DeviceSigningPrivateKey != first.PrivateKey {
		t.Fatal("login identity was not persisted")
	}
	cred.Token, cred.DevicePrivateKey = "test-token", "test-encryption-key"
	if err := SaveCredential(cred); err != nil {
		t.Fatal(err)
	}
	second, err := PrepareLoginSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatal("login rotated a healthy identity")
	}
	cred, _ = LoadCredential()
	if cred.Token != "test-token" || cred.DevicePrivateKey != "test-encryption-key" {
		t.Fatal("pre-login save lost existing credentials")
	}
	cred.DeviceSigningPrivateKey = ""
	if err := SaveCredential(cred); err != nil {
		t.Fatal(err)
	}
	recovered, err := PrepareLoginSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if recovered.PublicKey == first.PublicKey {
		t.Fatal("missing private key did not generate a replacement")
	}
	cred, _ = LoadCredential()
	if cred.DeviceSigningPrivateKey != recovered.PrivateKey {
		t.Fatal("replacement was not saved before login")
	}
}

func TestPrepareLoginSigningKeyRejectsUnreadableCredential(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	path, _ := CredentialPath()
	if err := SaveCredential(Credential{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareLoginSigningKey(); err == nil {
		t.Fatal("corrupt credential was silently overwritten")
	}
}
