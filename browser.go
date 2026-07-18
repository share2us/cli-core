package clicore

import (
	"errors"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
)

func OpenBrowser(rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return errors.New("browser URL is empty")
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
