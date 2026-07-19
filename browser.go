package clicore

import (
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
)

// validateBrowserURL only accepts real web URLs. OpenBrowser hands the value to
// the OS launcher (open / xdg-open / rundll32), and the value can come from a
// server response (device-code verification_uri), so a non-web scheme (file://,
// a custom-scheme handler) or a flag-like value must not reach the launcher.
func validateBrowserURL(rawURL string) error {
	if rawURL == "" {
		return errors.New("browser URL is empty")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid browser URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("refusing to open non-web URL scheme %q", parsed.Scheme)
	}
	return nil
}

func OpenBrowser(rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if err := validateBrowserURL(rawURL); err != nil {
		return err
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default:
		cmd = exec.Command("xdg-open", rawURL)
	}
	return cmd.Start()
}

func VerificationURL(code DeviceCodeResponse) string {
	if complete := strings.TrimSpace(code.VerificationURIComplete); complete != "" {
		return complete
	}
	baseURL := strings.TrimSpace(code.VerificationURI)
	if baseURL == "" {
		return ""
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.String() == "" {
		return baseURL
	}
	query := parsed.Query()
	query.Set("code", code.UserCode)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
