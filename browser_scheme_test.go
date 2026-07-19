package clicore

import "testing"

func TestValidateBrowserURL(t *testing.T) {
	ok := []string{
		"https://share2.us/activate?code=ABCD-1234",
		"http://localhost:3000/activate",
	}
	for _, u := range ok {
		if err := validateBrowserURL(u); err != nil {
			t.Errorf("validateBrowserURL(%q) = %v, want nil", u, err)
		}
	}

	bad := []string{
		"",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"ftp://example.com/x",
		"/relative/path",
		"-flag",
		"data:text/html,<script>",
	}
	for _, u := range bad {
		if err := validateBrowserURL(u); err == nil {
			t.Errorf("validateBrowserURL(%q) = nil, want an error", u)
		}
	}
}
