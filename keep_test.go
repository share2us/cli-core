package clicore

import "testing"

func TestExpiryForAPIKeepSentinels(t *testing.T) {
	for _, v := range []string{"0", "none", "never", "keep", "forever", "NONE", " never "} {
		expiresIn, noExpiry, err := ExpiryForAPI(v)
		if err != nil {
			t.Fatalf("ExpiryForAPI(%q) error = %v", v, err)
		}
		if !noExpiry {
			t.Errorf("ExpiryForAPI(%q) noExpiry = false, want true", v)
		}
		if expiresIn != "" {
			t.Errorf("ExpiryForAPI(%q) expiresIn = %q, want empty", v, expiresIn)
		}
	}
}

func TestExpiryForAPIFinite(t *testing.T) {
	expiresIn, noExpiry, err := ExpiryForAPI("7d")
	if err != nil {
		t.Fatalf("ExpiryForAPI(7d) error = %v", err)
	}
	if noExpiry {
		t.Errorf("ExpiryForAPI(7d) noExpiry = true, want false")
	}
	if expiresIn != "168h0m0s" {
		t.Errorf("ExpiryForAPI(7d) expiresIn = %q, want 168h0m0s", expiresIn)
	}
	if _, _, err := ExpiryForAPI("-3h"); err == nil {
		t.Error("ExpiryForAPI(-3h) should reject a non-positive duration")
	}
}

func TestContentClassTextFormats(t *testing.T) {
	cases := map[string]string{
		"config.yml":      "text",
		"config.yaml":     "text",
		"notes.md":        "markdown",
		"README.markdown": "markdown",
		"data.bin":        "binary",
	}
	for name, want := range cases {
		if got := ContentClassForNameAndType(name, ""); got != want {
			t.Errorf("ContentClassForNameAndType(%q) = %q, want %q", name, got, want)
		}
	}
}
