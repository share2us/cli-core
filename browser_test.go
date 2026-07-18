package clicore

import "testing"

func TestVerificationURLPrefersComplete(t *testing.T) {
	got := VerificationURL(DeviceCodeResponse{
		UserCode:                "ABCD-1234",
		VerificationURI:         "https://app.example.test/activate",
		VerificationURIComplete: "https://app.example.test/activate?code=ABCD-1234",
	})
	if got != "https://app.example.test/activate?code=ABCD-1234" {
		t.Fatalf("VerificationURL() = %q", got)
	}
}

func TestVerificationURLBuildsFallbackQuerySafely(t *testing.T) {
	got := VerificationURL(DeviceCodeResponse{
		UserCode:        "ABCD-1234",
		VerificationURI: "https://app.example.test/activate?next=%2Fdevices",
	})
	want := "https://app.example.test/activate?code=ABCD-1234&next=%2Fdevices"
	if got != want {
		t.Fatalf("VerificationURL() = %q, want %q", got, want)
	}
}

func TestVerificationURLEmptyWhenNoURI(t *testing.T) {
	if got := VerificationURL(DeviceCodeResponse{UserCode: "ABCD-1234"}); got != "" {
		t.Fatalf("VerificationURL() = %q, want empty", got)
	}
}
