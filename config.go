package clicore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	APIBaseSourceEnv     = "env"
	APIBaseSourceConfig  = "config"
	APIBaseSourceDefault = "default"
)

type Config struct {
	BaseURL   string `json:"base_url,omitempty"`
	Host      string `json:"host,omitempty"`
	ShareBase string `json:"share_base,omitempty"`
	MachineID string `json:"machine_id,omitempty"`
	// InstallID is a random, anonymous id generated once on first run and used
	// only for install counting (todo §J.4). Not tied to the account.
	InstallID string `json:"install_id,omitempty"`
	// InstallReported is set once the one-time install ping has been attempted.
	InstallReported bool `json:"install_reported,omitempty"`
	// Reshare is the LEGACY standing reshare default (ADR-024). Superseded by
	// Defaults.Reshare (O-C1); still read for back-compat. nil = unset.
	Reshare *bool `json:"reshare,omitempty"`
	// Defaults are standing per-user defaults for SAFE upload options (O-C1). Only
	// options that can't silently over-expose are defaultable here; an explicit flag
	// always overrides. Footgun options (password, one-time, recipients, visibility,
	// allow-secrets, device/contact) are deliberately NOT defaultable.
	Defaults *UploadDefaults `json:"defaults,omitempty"`
	// Devices are saved offline-share destinations, usable as `--dest <name>`.
	Devices []DeviceAlias `json:"devices,omitempty"`
	// TrustedPeers are alias names or IPs whose inbound offline transfers are
	// auto-accepted without a password (security trade-off; set with a warning).
	TrustedPeers []string `json:"trusted_peers,omitempty"`
}

// UploadDefaults holds tri-state standing defaults for upload options. A nil
// pointer / nil slice means "unset" (fall through to the compiled/server default).
type UploadDefaults struct {
	Expires        *string  `json:"expires,omitempty"`
	Reshare        *bool    `json:"reshare,omitempty"`
	Encrypt        *bool    `json:"encrypt,omitempty"`
	MaxViews       *uint64  `json:"max_views,omitempty"`
	NoScan         *bool    `json:"no_scan,omitempty"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	DeniedDomains  []string `json:"denied_domains,omitempty"`
}

// IsEmpty reports whether every standing default is unset, so callers can drop the
// Defaults object entirely (keeping `"defaults": {}` out of config.json).
func (d *UploadDefaults) IsEmpty() bool {
	if d == nil {
		return true
	}
	return d.Expires == nil && d.Reshare == nil && d.Encrypt == nil &&
		d.MaxViews == nil && d.NoScan == nil &&
		len(d.AllowedDomains) == 0 && len(d.DeniedDomains) == 0
}

// ResolvedReshareDefault returns the standing reshare default, preferring the new
// Defaults.Reshare and falling back to the legacy top-level Reshare (O-C1 migration).
func (c Config) ResolvedReshareDefault() *bool {
	if c.Defaults != nil && c.Defaults.Reshare != nil {
		v := *c.Defaults.Reshare
		return &v
	}
	if c.Reshare != nil {
		v := *c.Reshare
		return &v
	}
	return nil
}

func ConfigPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "share2us", "config.json"), nil
}

func LoadConfig() (Config, error) {
	path, err := ConfigPath()
	if err != nil {
		return Config{}, err
	}
	return LoadConfigAt(path)
}

func LoadConfigAt(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, os.ErrNotExist
		}
		return Config{}, err
	}
	var config Config
	if err := json.Unmarshal(raw, &config); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return config, nil
}

func SaveConfig(config Config) error {
	path, err := ConfigPath()
	if err != nil {
		return err
	}
	return SaveConfigAt(path, config)
}

func SaveConfigAt(path string, config Config) error {
	if config.Host != "" {
		host, err := NormalizeAPIHost(config.Host)
		if err != nil {
			return err
		}
		config.Host = host
	}
	if config.BaseURL != "" {
		baseURL, err := NormalizeBaseURL(config.BaseURL)
		if err != nil {
			return err
		}
		config.BaseURL = baseURL
	}
	if config.ShareBase != "" {
		shareBase, err := NormalizeShareBase(config.ShareBase)
		if err != nil {
			return err
		}
		config.ShareBase = shareBase
	}
	raw, err := json.MarshalIndent(config, "", "  ")
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

func NormalizeAPIHost(value string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(value), "/")
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid host URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("host must be an absolute http(s) URL")
	}
	if parsed.Host == "" {
		return "", errors.New("host must include a host name")
	}
	return trimmed, nil
}

func NormalizeShareBase(value string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(value), "/")
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid share base URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("share base must be an absolute http(s) URL")
	}
	if parsed.Host == "" {
		return "", errors.New("share base must include a host name")
	}
	return trimmed, nil
}

func NormalizeBaseURL(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", errors.New("base_url is required")
	}
	if strings.ContainsAny(trimmed, " \t\r\n") {
		return "", errors.New("base_url must not contain spaces")
	}
	host := trimmed
	if strings.Contains(host, "://") {
		parsed, err := url.Parse(host)
		if err != nil {
			return "", fmt.Errorf("invalid base_url: %w", err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return "", errors.New("base_url URL must use http(s)")
		}
		host = parsed.Hostname()
	} else if strings.ContainsAny(host, "/?#") {
		return "", errors.New("base_url must be a host name, not a path")
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, prefix := range []string{"api.", "s.", "app.", "admin."} {
		host = strings.TrimPrefix(host, prefix)
	}
	if host == "" || !strings.Contains(host, ".") {
		return "", errors.New("base_url must be a dotted host name")
	}
	if strings.ContainsAny(host, "/:?#[]@") {
		return "", errors.New("base_url must be a plain host name")
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("base_url must be a valid host name")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return "", errors.New("base_url must be a valid host name")
		}
	}
	return host, nil
}

func APIBaseFromBaseURL(baseURL string) (string, error) {
	baseURL, err := NormalizeBaseURL(baseURL)
	if err != nil {
		return "", err
	}
	return "https://api." + baseURL, nil
}

func ShareBaseFromBaseURL(baseURL string) (string, error) {
	baseURL, err := NormalizeBaseURL(baseURL)
	if err != nil {
		return "", err
	}
	return "https://s." + baseURL, nil
}

func ResolveBaseURL() (string, string, error) {
	if value := os.Getenv("SHARE2US_BASE_URL"); value != "" {
		baseURL, err := NormalizeBaseURL(value)
		return baseURL, APIBaseSourceEnv, err
	}
	config, err := LoadConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	if err == nil && strings.TrimSpace(config.BaseURL) != "" {
		baseURL, err := NormalizeBaseURL(config.BaseURL)
		return baseURL, APIBaseSourceConfig, err
	}
	return DefaultBaseURL, APIBaseSourceDefault, nil
}

func ResolveAPIBase() (string, string, error) {
	if value := os.Getenv("SHARE2US_API_BASE"); value != "" {
		host, err := NormalizeAPIHost(value)
		return host, APIBaseSourceEnv, err
	}
	if value := os.Getenv("SHARE2US_BASE_URL"); value != "" {
		host, err := APIBaseFromBaseURL(value)
		return host, APIBaseSourceEnv, err
	}
	config, err := LoadConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	if err == nil && strings.TrimSpace(config.Host) != "" {
		host, err := NormalizeAPIHost(config.Host)
		return host, APIBaseSourceConfig, err
	}
	if err == nil && strings.TrimSpace(config.BaseURL) != "" {
		host, err := APIBaseFromBaseURL(config.BaseURL)
		return host, APIBaseSourceConfig, err
	}
	host, err := APIBaseFromBaseURL(DefaultBaseURL)
	return host, APIBaseSourceDefault, err
}

func ResolveShareBase() (string, string, error) {
	if value := os.Getenv("SHARE2US_SHARE_BASE_URL"); value != "" {
		host, err := NormalizeShareBase(value)
		return host, APIBaseSourceEnv, err
	}
	if value := os.Getenv("SHARE2US_SHARE_BASE"); value != "" {
		host, err := NormalizeShareBase(value)
		return host, APIBaseSourceEnv, err
	}
	if value := os.Getenv("SHARE2US_BASE_URL"); value != "" {
		host, err := ShareBaseFromBaseURL(value)
		return host, APIBaseSourceEnv, err
	}
	config, err := LoadConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	if err == nil && strings.TrimSpace(config.ShareBase) != "" {
		host, err := NormalizeShareBase(config.ShareBase)
		return host, APIBaseSourceConfig, err
	}
	if err == nil && strings.TrimSpace(config.BaseURL) != "" {
		host, err := ShareBaseFromBaseURL(config.BaseURL)
		return host, APIBaseSourceConfig, err
	}
	host, err := ShareBaseFromBaseURL(DefaultBaseURL)
	return host, APIBaseSourceDefault, err
}

func DownloadGatewayURL(apiBase, publicID string) (string, error) {
	apiBase, err := NormalizeAPIHost(apiBase)
	if err != nil {
		return "", err
	}
	publicID = strings.TrimSpace(publicID)
	if publicID == "" {
		return "", errors.New("public id is required")
	}
	if strings.ContainsAny(publicID, "/?#") {
		return "", errors.New("invalid public id")
	}
	return apiBase + "/d/" + url.PathEscape(publicID), nil
}
