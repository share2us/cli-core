package clicore

import "testing"

func TestScanBytesHighConfidence(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantHigh bool
	}{
		{"private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----\n", true},
		{"aws access key id", "aws_access_key_id = AKIAZ3XYQ7KHT9WPLM4C\n", true},
		{"generic api key is soft", `api_key = "abcdef0123456789abcdef0123456789"`, false},
		{"clean", "the quick brown fox jumps over the lazy dog\n", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ScanBytesForSecrets([]byte(tt.body), SecretScanOptions{})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if r.HasHighConfidenceSecret() != tt.wantHigh {
				t.Fatalf("HasHighConfidenceSecret()=%v want %v (findings: %+v)", r.HasHighConfidenceSecret(), tt.wantHigh, r.Findings)
			}
		})
	}
}

func TestIsHighConfidenceSecretRule(t *testing.T) {
	if IsHighConfidenceSecretRule("generic-api-key") {
		t.Fatal("generic-api-key must be low-confidence")
	}
	if !IsHighConfidenceSecretRule("private-key") {
		t.Fatal("private-key must be high-confidence")
	}
	if IsHighConfidenceSecretRule("") {
		t.Fatal("empty rule id is not a secret")
	}
}

func TestScanBytesSkipsBinary(t *testing.T) {
	r, err := ScanBytesForSecrets([]byte{0x00, 0x01, 0x02, 0xff}, SecretScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !r.Skipped || r.HasHighConfidenceSecret() {
		t.Fatalf("binary should be skipped with no findings: %+v", r)
	}
}
