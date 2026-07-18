package clicore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUsage(t *testing.T) {
	got := Usage("share2us")
	for _, want := range []string{"share2us " + FullVersion(), "share2us login [--host URL]", "share2us config set-base-url <domain>", "share2us config set-host <url>", "share2us config show", "share2us signout <device-id|device-name>", "share2us update [--host URL] [--version VERSION]", "share2us tui", "share2us <file>", "--new|--fresh", "--allow-secrets|--no-scan", "share2us pull <url-or-public-id>", "share2us ls", "share2us rm|delete <serial|public-id>", "alias share=share2us", "SHARE2US_BASE_URL", "SHARE2US_API_BASE"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Usage() missing %q in:\n%s", want, got)
		}
	}
}

func TestFullVersionUsesBuildVersion(t *testing.T) {
	oldVersion := Version
	oldBuildVersion := BuildVersion
	t.Cleanup(func() {
		Version = oldVersion
		BuildVersion = oldBuildVersion
	})
	BuildVersion = "20260708123045"
	Version = "ignored"
	if got := FullVersion(); got != "20260708123045" {
		t.Fatalf("FullVersion() = %q", got)
	}
	BuildVersion = ""
	Version = "20260708111111"
	if got := FullVersion(); got != "20260708111111" {
		t.Fatalf("FullVersion() fallback = %q", got)
	}
	BuildVersion = ""
	Version = ""
	if got := FullVersion(); got != "dev" {
		t.Fatalf("FullVersion() default = %q", got)
	}
}

func TestScanFileForSecretsFindsAndRedactsPrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	material := "MIIEpAIBAAKCAQEA0" + strings.Repeat("testredacted", 3)
	secret := strings.Join([]string{
		"-----BEGIN " + "RSA PRIVATE KEY-----",
		material,
		"-----END " + "RSA PRIVATE KEY-----",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	result, err := ScanFileForSecrets(path, SecretScanOptions{})
	if err != nil {
		t.Fatalf("ScanFileForSecrets() error = %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatalf("expected findings, got %+v", result)
	}
	if !strings.Contains(result.Findings[0].Redacted, "REDACTED") {
		t.Fatalf("redacted finding missing marker: %+v", result.Findings[0])
	}
	if strings.Contains(result.Findings[0].Redacted, material) {
		t.Fatalf("redacted finding leaked secret: %+v", result.Findings[0])
	}
}

func TestScanFileForSecretsCleanAndBinary(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.txt")
	if err := os.WriteFile(clean, []byte("hello from share2us\n"), 0o600); err != nil {
		t.Fatalf("write clean file: %v", err)
	}
	result, err := ScanFileForSecrets(clean, SecretScanOptions{})
	if err != nil {
		t.Fatalf("ScanFileForSecrets(clean) error = %v", err)
	}
	if result.Skipped || len(result.Findings) != 0 {
		t.Fatalf("clean result = %+v", result)
	}

	binary := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(binary, []byte{0x00, 0x01, 0x02}, 0o600); err != nil {
		t.Fatalf("write binary file: %v", err)
	}
	result, err = ScanFileForSecrets(binary, SecretScanOptions{})
	if err != nil {
		t.Fatalf("ScanFileForSecrets(binary) error = %v", err)
	}
	if !result.Skipped || result.SkipReason != "binary content" {
		t.Fatalf("binary result = %+v", result)
	}
}

func TestSourceRefAndRegistryHelpers(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "hello.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("Abs() error = %v", err)
	}
	wantSum := sha256.Sum256([]byte(absPath))

	gotRef, gotAbs, err := SourceRefForPath(path)
	if err != nil {
		t.Fatalf("SourceRefForPath() error = %v", err)
	}
	if gotAbs != absPath || gotRef != fmt.Sprintf("%x", wantSum[:]) {
		t.Fatalf("SourceRefForPath() = %q, %q; want %q, %q", gotRef, gotAbs, fmt.Sprintf("%x", wantSum[:]), absPath)
	}

	registry := AddSourceRegistryEntry(nil, gotAbs, SourceRegistryEntry{PublicID: "pub-1", Link: "https://s.example.test/pub-1"})
	if err := SaveSourceRegistry(registry); err != nil {
		t.Fatalf("SaveSourceRegistry() error = %v", err)
	}
	loaded, err := LoadSourceRegistry()
	if err != nil {
		t.Fatalf("LoadSourceRegistry() error = %v", err)
	}
	if loaded[gotAbs].PublicID != "pub-1" || loaded[gotAbs].Link != "https://s.example.test/pub-1" {
		t.Fatalf("loaded registry = %+v", loaded)
	}
}

func TestListIndexHelpers(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	entries := []ListIndexEntry{
		{Serial: 1, PublicID: "pub-1", FileName: "one.txt"},
		{Serial: 2, PublicID: "pub-2", FileName: "two.txt"},
	}
	if err := SaveListIndex(entries); err != nil {
		t.Fatalf("SaveListIndex() error = %v", err)
	}
	path, err := ListIndexPath()
	if err != nil {
		t.Fatalf("ListIndexPath() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat list index: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 0600", got)
	}
	loaded, err := LoadListIndex()
	if err != nil {
		t.Fatalf("LoadListIndex() error = %v", err)
	}
	if len(loaded) != 2 || loaded[1].Serial != 2 || loaded[1].PublicID != "pub-2" || loaded[1].FileName != "two.txt" {
		t.Fatalf("loaded = %+v", loaded)
	}
}

func TestUpdateCheckCacheRoundTrip(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	want := UpdateCheckCache{
		LastCheckedAt: time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC),
		LatestVersion: "20260708123045",
	}
	if err := SaveUpdateCheckCache(want); err != nil {
		t.Fatalf("SaveUpdateCheckCache() error = %v", err)
	}
	got, err := LoadUpdateCheckCache()
	if err != nil {
		t.Fatalf("LoadUpdateCheckCache() error = %v", err)
	}
	if !got.LastCheckedAt.Equal(want.LastCheckedAt) || got.LatestVersion != want.LatestVersion {
		t.Fatalf("cache = %+v, want %+v", got, want)
	}
}

func TestCacheManifestHelpers(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	objectPath := filepath.Join(t.TempDir(), "object")
	if err := os.WriteFile(objectPath, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write object: %v", err)
	}
	sum, err := FileSHA256(objectPath)
	if err != nil {
		t.Fatalf("FileSHA256() error = %v", err)
	}
	manifest := AddCacheEntry(nil, "pub-1", CacheEntry{
		Path:      objectPath,
		SizeBytes: 5,
		SHA256:    sum,
		FileName:  "hello.txt",
		PulledAt:  time.Now().UTC(),
	})
	if !CacheEntryIsLocal(manifest["pub-1"]) {
		t.Fatal("CacheEntryIsLocal() = false, want true")
	}
	if err := SaveCacheManifest(manifest); err != nil {
		t.Fatalf("SaveCacheManifest() error = %v", err)
	}
	manifestPath, err := CacheManifestPath()
	if err != nil {
		t.Fatalf("CacheManifestPath() error = %v", err)
	}
	info, err := os.Stat(manifestPath)
	if err != nil {
		t.Fatalf("stat manifest: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode = %v, want 0600", info.Mode().Perm())
	}
	loaded, err := LoadCacheManifest()
	if err != nil {
		t.Fatalf("LoadCacheManifest() error = %v", err)
	}
	if loaded["pub-1"].SHA256 != sum {
		t.Fatalf("loaded manifest = %+v", loaded)
	}
	loaded = RemoveCacheEntry(loaded, "pub-1")
	if _, ok := loaded["pub-1"]; ok {
		t.Fatal("RemoveCacheEntry left pub-1")
	}
}

func TestConfigStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "share2us", "config.json")

	if err := SaveConfigAt(path, Config{Host: "https://api.example.test/"}); err != nil {
		t.Fatalf("SaveConfigAt() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 0600", got)
	}

	loaded, err := LoadConfigAt(path)
	if err != nil {
		t.Fatalf("LoadConfigAt() error = %v", err)
	}
	if loaded.Host != "https://api.example.test" {
		t.Fatalf("Host = %q", loaded.Host)
	}
}

func TestNormalizeBaseURLAndDerive(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "staging.share2.us", want: "staging.share2.us"},
		{in: "https://api.staging.share2.us/path?q=1", want: "staging.share2.us"},
		{in: "s.share2.us", want: "share2.us"},
		{in: "APP.EXAMPLE.TEST.", want: "example.test"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := NormalizeBaseURL(tt.in)
			if err != nil {
				t.Fatalf("NormalizeBaseURL() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}

	apiBase, err := APIBaseFromBaseURL("https://api.staging.share2.us/ignored")
	if err != nil {
		t.Fatalf("APIBaseFromBaseURL() error = %v", err)
	}
	if apiBase != "https://api.staging.share2.us" {
		t.Fatalf("APIBaseFromBaseURL() = %q", apiBase)
	}
	shareBase, err := ShareBaseFromBaseURL("staging.share2.us")
	if err != nil {
		t.Fatalf("ShareBaseFromBaseURL() error = %v", err)
	}
	if shareBase != "https://s.staging.share2.us" {
		t.Fatalf("ShareBaseFromBaseURL() = %q", shareBase)
	}

	for _, bad := range []string{"", "localhost", "staging share2.us", "staging.share2.us/path", "staging.share2.us:443"} {
		if _, err := NormalizeBaseURL(bad); err == nil {
			t.Fatalf("NormalizeBaseURL(%q) accepted invalid input", bad)
		}
	}
}

func TestResolveAPIBasePrecedence(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("SHARE2US_API_BASE", "")
	t.Setenv("SHARE2US_BASE_URL", "")

	host, source, err := ResolveAPIBase()
	if err != nil {
		t.Fatalf("ResolveAPIBase() default error = %v", err)
	}
	if host != DefaultAPIBase || source != APIBaseSourceDefault {
		t.Fatalf("default host/source = %q/%q", host, source)
	}

	if err := SaveConfig(Config{BaseURL: "staging.share2.us"}); err != nil {
		t.Fatalf("SaveConfig() base_url error = %v", err)
	}
	host, source, err = ResolveAPIBase()
	if err != nil {
		t.Fatalf("ResolveAPIBase() base_url config error = %v", err)
	}
	if host != "https://api.staging.share2.us" || source != APIBaseSourceConfig {
		t.Fatalf("base_url config host/source = %q/%q", host, source)
	}

	if err := SaveConfig(Config{Host: "https://configured.example.test/", BaseURL: "staging.share2.us"}); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}
	host, source, err = ResolveAPIBase()
	if err != nil {
		t.Fatalf("ResolveAPIBase() config error = %v", err)
	}
	if host != "https://configured.example.test" || source != APIBaseSourceConfig {
		t.Fatalf("config host/source = %q/%q", host, source)
	}

	t.Setenv("SHARE2US_BASE_URL", "api.env-base.example.test")
	host, source, err = ResolveAPIBase()
	if err != nil {
		t.Fatalf("ResolveAPIBase() base env error = %v", err)
	}
	if host != "https://api.env-base.example.test" || source != APIBaseSourceEnv {
		t.Fatalf("base env host/source = %q/%q", host, source)
	}

	t.Setenv("SHARE2US_API_BASE", "https://env.example.test/")
	host, source, err = ResolveAPIBase()
	if err != nil {
		t.Fatalf("ResolveAPIBase() env error = %v", err)
	}
	if host != "https://env.example.test" || source != APIBaseSourceEnv {
		t.Fatalf("env host/source = %q/%q", host, source)
	}
}

func TestResolveShareBasePrecedence(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("SHARE2US_SHARE_BASE_URL", "")
	t.Setenv("SHARE2US_SHARE_BASE", "")
	t.Setenv("SHARE2US_BASE_URL", "")

	host, source, err := ResolveShareBase()
	if err != nil {
		t.Fatalf("ResolveShareBase() default error = %v", err)
	}
	if host != DefaultShareBase || source != APIBaseSourceDefault {
		t.Fatalf("default host/source = %q/%q", host, source)
	}

	if err := SaveConfig(Config{BaseURL: "staging.share2.us"}); err != nil {
		t.Fatalf("SaveConfig() base_url error = %v", err)
	}
	host, source, err = ResolveShareBase()
	if err != nil {
		t.Fatalf("ResolveShareBase() base_url config error = %v", err)
	}
	if host != "https://s.staging.share2.us" || source != APIBaseSourceConfig {
		t.Fatalf("base_url config host/source = %q/%q", host, source)
	}

	if err := SaveConfig(Config{ShareBase: "https://configured-share.example.test/d/", BaseURL: "staging.share2.us"}); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}
	host, source, err = ResolveShareBase()
	if err != nil {
		t.Fatalf("ResolveShareBase() config error = %v", err)
	}
	if host != "https://configured-share.example.test/d" || source != APIBaseSourceConfig {
		t.Fatalf("config host/source = %q/%q", host, source)
	}

	t.Setenv("SHARE2US_BASE_URL", "s.env-base.example.test")
	host, source, err = ResolveShareBase()
	if err != nil {
		t.Fatalf("ResolveShareBase() base env error = %v", err)
	}
	if host != "https://s.env-base.example.test" || source != APIBaseSourceEnv {
		t.Fatalf("base env host/source = %q/%q", host, source)
	}

	t.Setenv("SHARE2US_SHARE_BASE", "https://share-legacy.example.test/")
	host, source, err = ResolveShareBase()
	if err != nil {
		t.Fatalf("ResolveShareBase() legacy env error = %v", err)
	}
	if host != "https://share-legacy.example.test" || source != APIBaseSourceEnv {
		t.Fatalf("legacy env host/source = %q/%q", host, source)
	}

	t.Setenv("SHARE2US_SHARE_BASE_URL", "https://share-env.example.test/")
	host, source, err = ResolveShareBase()
	if err != nil {
		t.Fatalf("ResolveShareBase() env error = %v", err)
	}
	if host != "https://share-env.example.test" || source != APIBaseSourceEnv {
		t.Fatalf("env host/source = %q/%q", host, source)
	}
}

func TestDownloadGatewayURL(t *testing.T) {
	got, err := DownloadGatewayURL("https://api.example.test/", "pub-1")
	if err != nil {
		t.Fatalf("DownloadGatewayURL() error = %v", err)
	}
	if got != "https://api.example.test/d/pub-1" {
		t.Fatalf("DownloadGatewayURL() = %q", got)
	}

	if _, err := DownloadGatewayURL("https://api.example.test", "bad/id"); err == nil {
		t.Fatalf("DownloadGatewayURL() accepted invalid public id")
	}
}

func TestDetectDeviceMetadata(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	metadata, err := DetectDeviceMetadata("Workstation")
	if err != nil {
		t.Fatalf("DetectDeviceMetadata() error = %v", err)
	}
	if metadata.DeviceName != "Workstation" || metadata.OS == "" || metadata.Arch == "" {
		t.Fatalf("metadata = %+v", metadata)
	}
	if len(metadata.MachineID) != 64 {
		t.Fatalf("machine id hash length = %d, want 64", len(metadata.MachineID))
	}
}

func TestDurationForAPI(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "24h", want: "24h0m0s"},
		{in: "7d", want: "168h0m0s"},
		{in: "12", want: "12h0m0s"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := DurationForAPI(tt.in)
			if err != nil {
				t.Fatalf("DurationForAPI() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("DurationForAPI() = %q, want %q", got, tt.want)
			}
		})
	}
	if _, err := DurationForAPI("0"); err == nil {
		t.Fatal("DurationForAPI(0) error = nil, want error")
	}
}

func TestClientDeviceFlowPendingThenApproved(t *testing.T) {
	polls := 0
	var deviceRequest DeviceCodeRequest
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/device-codes":
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&deviceRequest); err != nil {
				t.Fatalf("decode device request: %v", err)
			}
			writeJSON(w, map[string]any{
				"device_code":      "dev-1",
				"user_code":        "ABCD-1234",
				"verification_uri": "https://app.example.test/activate",
				"interval":         1,
				"expires_in":       600,
			})
		case "/v1/auth/device-codes/dev-1/token":
			polls++
			if polls == 1 {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, map[string]any{"error": map[string]string{"code": "authorization_pending", "message": "pending", "request_id": "req-1"}})
				return
			}
			writeJSON(w, map[string]any{"credential": "s2s_test", "device_session_id": "sess-1", "scopes": []string{"account.read"}})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})

	client := NewClient("https://api.example.test", "")
	client.HTTPClient = handlerClient(handler)
	code, err := client.StartDeviceCode(t.Context(), DeviceCodeRequest{
		DeviceName:    "Workstation",
		MachineID:     "abc123",
		OS:            "linux",
		Arch:          "amd64",
		ClientVersion: FullVersion(),
	})
	if err != nil {
		t.Fatalf("StartDeviceCode() error = %v", err)
	}
	if deviceRequest.DeviceName != "Workstation" || deviceRequest.MachineID != "abc123" || deviceRequest.ClientVersion != FullVersion() {
		t.Fatalf("device request = %+v", deviceRequest)
	}
	if code.DeviceCode != "dev-1" || code.UserCode != "ABCD-1234" || code.Interval != 1 {
		t.Fatalf("device code = %+v", code)
	}

	_, err = client.PollDeviceToken(t.Context(), code.DeviceCode)
	if !IsAuthorizationPending(err) {
		t.Fatalf("PollDeviceToken() error = %v, want authorization pending", err)
	}

	token, err := client.PollDeviceToken(t.Context(), code.DeviceCode)
	if err != nil {
		t.Fatalf("PollDeviceToken() approved error = %v", err)
	}
	if token.Credential != "s2s_test" {
		t.Fatalf("credential = %q", token.Credential)
	}
}

func TestClientDeviceLimitErrorParsesSessions(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/device-codes/dev-1/token" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusForbidden)
		writeJSON(w, map[string]any{
			"error": map[string]string{
				"code":       "device_limit_reached",
				"message":    "device/session limit reached",
				"request_id": "req-limit",
			},
			"limit": 2,
			"sessions": []map[string]any{{
				"id":           "sess-1",
				"device_name":  "Laptop",
				"client_type":  "cli",
				"created_at":   "2026-07-10T10:00:00Z",
				"last_used_at": "2026-07-10T11:00:00Z",
			}},
		})
	})
	client := NewClient("https://api.example.test", "")
	client.HTTPClient = handlerClient(handler)

	_, err := client.PollDeviceToken(t.Context(), "dev-1")
	if !IsDeviceLimitReached(err) {
		t.Fatalf("PollDeviceToken() error = %v, want device limit", err)
	}
	details, ok := DeviceLimitDetailsFromError(err)
	if !ok {
		t.Fatalf("DeviceLimitDetailsFromError() ok = false")
	}
	if details.Limit != 2 || len(details.Sessions) != 1 || details.Sessions[0].ID != "sess-1" || details.Sessions[0].DeviceName != "Laptop" {
		t.Fatalf("details = %+v", details)
	}
}

func TestClientRevokesDeviceSessions(t *testing.T) {
	var paths []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		if strings.Contains(r.URL.Path, "device-codes") {
			var body struct {
				SessionID string `json:"session_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode revoke body: %v", err)
			}
			if body.SessionID != "sess-2" {
				t.Fatalf("body session_id = %q", body.SessionID)
			}
		}
		writeJSON(w, map[string]string{"status": "revoked"})
	})
	client := NewClient("https://api.example.test", "s2s_test")
	client.HTTPClient = handlerClient(handler)

	if err := client.RevokeDeviceSession(t.Context(), "sess-1"); err != nil {
		t.Fatalf("RevokeDeviceSession() error = %v", err)
	}
	if err := client.RevokeDeviceSessionWithDeviceCode(t.Context(), "dev-1", "sess-2"); err != nil {
		t.Fatalf("RevokeDeviceSessionWithDeviceCode() error = %v", err)
	}
	want := []string{"/v1/auth/sessions/sess-1/revoke", "/v1/auth/device-codes/dev-1/revoke-session"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
}

func TestClientMeListAndErrorEnvelope(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer s2s_test" {
			t.Fatalf("Authorization = %q", got)
		}
		switch r.URL.Path {
		case "/v1/auth/me":
			writeJSON(w, map[string]string{"account_id": "acct-1", "user_id": "user-1", "plan_name": "Free"})
		case "/v1/shares":
			writeJSON(w, map[string]any{"shares": []map[string]any{{"public_id": "pub-1", "file_name": "a.txt", "size_bytes": 3, "status": "ready", "expires_at": "2026-07-03T00:00:00Z", "download_count": 1}}})
		case "/v1/auth/logout":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusForbidden)
			writeJSON(w, map[string]any{"error": map[string]string{"code": "forbidden", "message": "nope", "request_id": "req-2"}})
		}
	})

	client := NewClient("https://api.example.test", "s2s_test")
	client.HTTPClient = handlerClient(handler)
	me, err := client.Me(t.Context())
	if err != nil {
		t.Fatalf("Me() error = %v", err)
	}
	if me.AccountID != "acct-1" || me.PlanName != "Free" {
		t.Fatalf("me = %+v", me)
	}

	shares, err := client.ListShares(t.Context())
	if err != nil {
		t.Fatalf("ListShares() error = %v", err)
	}
	if len(shares.Shares) != 1 || shares.Shares[0].FileName != "a.txt" {
		t.Fatalf("shares = %+v", shares)
	}
	if err := client.Logout(t.Context()); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	err = client.doJSON(t.Context(), http.MethodGet, "/blocked", nil, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %T %v, want APIError", err, err)
	}
	if apiErr.Status != http.StatusForbidden || apiErr.Code != "forbidden" || apiErr.RequestID != "req-2" {
		t.Fatalf("api error = %+v", apiErr)
	}
}

func TestClientCheckUpdate(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/cli/update" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.URL.Query().Get("version") != FullVersion() || r.URL.Query().Get("os") != "linux" || r.URL.Query().Get("arch") != "amd64" {
			t.Fatalf("query = %s", r.URL.RawQuery)
		}
		writeJSON(w, map[string]any{
			"current_version":  FullVersion(),
			"latest_version":   "20260708123045",
			"update_available": true,
			"platform":         "linux/amd64",
			"downloads": map[string]any{
				"archive_url": "https://share2.us/downloads/share2us_linux_amd64.tar.gz",
				"crc32":       "2526929905",
				"size_bytes":  8959837,
			},
		})
	})
	client := NewClient("https://api.example.test", "")
	client.HTTPClient = handlerClient(handler)

	got, err := client.CheckUpdate(t.Context(), FullVersion(), "linux", "amd64")
	if err != nil {
		t.Fatalf("CheckUpdate() error = %v", err)
	}
	if !got.UpdateAvailable || got.LatestVersion != "20260708123045" || got.Downloads.CRC32 != "2526929905" || got.Downloads.SizeBytes != 8959837 {
		t.Fatalf("update = %+v", got)
	}
}

func TestClientDoJSONRetries429RetryAfterThenSucceeds(t *testing.T) {
	restore := stubRateLimitSleep(t)
	defer restore()

	attempts := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			writeJSON(w, map[string]any{"error": map[string]string{"code": "rate_limited", "message": "slow down"}})
			return
		}
		writeJSON(w, map[string]string{"account_id": "acct-1", "user_id": "user-1"})
	})
	client := NewClient("https://api.example.test", "s2s_test")
	client.HTTPClient = handlerClient(handler)

	me, err := client.Me(t.Context())
	if err != nil {
		t.Fatalf("Me() error = %v", err)
	}
	if me.AccountID != "acct-1" || attempts != 2 {
		t.Fatalf("me = %+v attempts=%d", me, attempts)
	}
}

func TestClientDoJSONPersistent429ReturnsRateLimitedError(t *testing.T) {
	restore := stubRateLimitSleep(t)
	defer restore()

	attempts := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusTooManyRequests)
		writeJSON(w, map[string]any{"error": map[string]string{"code": "too_many_requests", "message": "try later"}})
	})
	client := NewClient("https://api.example.test", "")
	client.HTTPClient = handlerClient(handler)

	err := client.doJSON(t.Context(), http.MethodGet, "/v1/test", nil, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %T %v, want APIError", err, err)
	}
	if apiErr.Status != http.StatusTooManyRequests || apiErr.Code != "rate_limited" || !strings.Contains(apiErr.Message, "rate limited by the server") {
		t.Fatalf("api error = %+v", apiErr)
	}
	if attempts != maxRateLimitAttempts {
		t.Fatalf("attempts = %d, want %d", attempts, maxRateLimitAttempts)
	}
}

func TestClientDoJSONPlainText429BlockReturnsAppealMessageWithoutExhaustingRetries(t *testing.T) {
	restore := stubRateLimitSleep(t)
	defer restore()

	attempts := 0
	body := "Access temporarily blocked due to suspicious activity. If this is a mistake, appeal at https://app.share2.us/appeal"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, body)
	})
	client := NewClient("https://api.example.test", "")
	client.HTTPClient = handlerClient(handler)

	err := client.doJSON(t.Context(), http.MethodGet, "/v1/test", nil, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %T %v, want APIError", err, err)
	}
	if apiErr.Code != "rate_limited" || apiErr.Message != body {
		t.Fatalf("api error = %+v", apiErr)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestClientDoJSONCloudflareChallengeReturnsDistinctError(t *testing.T) {
	attempts := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("cf-mitigated", "challenge")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "<html><title>challenge</title></html>")
	})
	client := NewClient("https://api.example.test", "")
	client.HTTPClient = handlerClient(handler)

	err := client.doJSON(t.Context(), http.MethodGet, "/v1/test", nil, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %T %v, want APIError", err, err)
	}
	if apiErr.Status != http.StatusForbidden || apiErr.Code != "cloudflare_challenge" || !strings.Contains(apiErr.Message, "Cloudflare challenge") {
		t.Fatalf("api error = %+v", apiErr)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestClientDownloadURLRetries429ThenSucceeds(t *testing.T) {
	restore := stubRateLimitSleep(t)
	defer restore()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			writeJSON(w, map[string]any{"error": map[string]string{"code": "rate_limited"}})
			return
		}
		fmt.Fprint(w, "downloaded")
	}))
	defer server.Close()

	var out strings.Builder
	client := NewClient("https://api.example.test", "")
	if err := client.DownloadURL(t.Context(), server.URL, &out); err != nil {
		t.Fatalf("DownloadURL() error = %v", err)
	}
	if out.String() != "downloaded" || attempts != 2 {
		t.Fatalf("out = %q attempts=%d", out.String(), attempts)
	}
}

func TestClientNormal2xxAndJSON400BehaviorUnchanged(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/me":
			writeJSON(w, map[string]string{"account_id": "acct-ok", "user_id": "user-ok"})
		default:
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": map[string]string{"code": "bad_request", "message": "still json", "request_id": "req-json"}})
		}
	})
	client := NewClient("https://api.example.test", "")
	client.HTTPClient = handlerClient(handler)

	me, err := client.Me(t.Context())
	if err != nil {
		t.Fatalf("Me() error = %v", err)
	}
	if me.AccountID != "acct-ok" {
		t.Fatalf("me = %+v", me)
	}

	err = client.doJSON(t.Context(), http.MethodGet, "/v1/bad", nil, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %T %v, want APIError", err, err)
	}
	if apiErr.Status != http.StatusBadRequest || apiErr.Code != "bad_request" || apiErr.Message != "still json" || apiErr.RequestID != "req-json" {
		t.Fatalf("api error = %+v", apiErr)
	}
}

func TestClientShareManagementAndUsage(t *testing.T) {
	var expiryBody struct {
		ExpiresAt string `json:"expires_at"`
	}
	var deleted bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer s2s_test" {
			t.Fatalf("Authorization = %q", got)
		}
		switch r.URL.Path {
		case "/v1/shares/pub-1/revoke":
			if r.Method != http.MethodPost {
				t.Fatalf("revoke method = %s", r.Method)
			}
			writeJSON(w, map[string]any{"public_id": "pub-1", "file_name": "a.txt", "status": "revoked"})
		case "/v1/shares/pub-1/expiry":
			if r.Method != http.MethodPost {
				t.Fatalf("expiry method = %s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&expiryBody); err != nil {
				t.Fatalf("decode expiry body: %v", err)
			}
			writeJSON(w, map[string]any{"public_id": "pub-1", "file_name": "a.txt", "status": "ready", "expires_at": expiryBody.ExpiresAt})
		case "/v1/shares/pub-1":
			if r.Method != http.MethodDelete {
				t.Fatalf("delete method = %s", r.Method)
			}
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		case "/v1/usage":
			if r.Method != http.MethodGet {
				t.Fatalf("usage method = %s", r.Method)
			}
			writeJSON(w, map[string]any{
				"storage_used_bytes":  12,
				"storage_quota_bytes": 1024,
				"active_shares":       1,
				"max_active_shares":   25,
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})

	client := NewClient("https://api.example.test", "s2s_test")
	client.HTTPClient = handlerClient(handler)

	revoked, err := client.RevokeShare(t.Context(), "pub-1")
	if err != nil {
		t.Fatalf("RevokeShare() error = %v", err)
	}
	if revoked.Status != "revoked" {
		t.Fatalf("revoked = %+v", revoked)
	}
	extended, err := client.ExtendExpiry(t.Context(), "pub-1", time.Hour)
	if err != nil {
		t.Fatalf("ExtendExpiry() error = %v", err)
	}
	if _, err := time.Parse(time.RFC3339, expiryBody.ExpiresAt); err != nil {
		t.Fatalf("expires_at = %q: %v", expiryBody.ExpiresAt, err)
	}
	if extended.ExpiresAt != expiryBody.ExpiresAt {
		t.Fatalf("extended = %+v body=%+v", extended, expiryBody)
	}
	if err := client.DeleteShare(t.Context(), "pub-1"); err != nil {
		t.Fatalf("DeleteShare() error = %v", err)
	}
	if !deleted {
		t.Fatalf("delete was not called")
	}
	usage, err := client.Usage(t.Context())
	if err != nil {
		t.Fatalf("Usage() error = %v", err)
	}
	if usage.StorageUsedBytes != 12 || usage.MaxActiveShares != 25 {
		t.Fatalf("usage = %+v", usage)
	}
}

func TestClientUploadCreatePutComplete(t *testing.T) {
	var uploaded string
	var authSeen bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/uploads":
			authSeen = r.Header.Get("Authorization") == "Bearer s2s_test"
			var req UploadCreateRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode create upload: %v", err)
			}
			if req.FileName != "a.txt" || req.SizeBytes != 5 || req.SHA256 == "" || req.SourceRef != strings.Repeat("c", 64) || !req.New {
				t.Fatalf("create request = %+v", req)
			}
			if req.RecipientEmail != "recipient@example.test" || len(req.Targets) != 1 || req.Targets[0].TargetDeviceSessionID != "00000000-0000-0000-0000-000000000201" || req.Targets[0].SealedKey != "sealed" {
				t.Fatalf("teammate request fields = %+v", req)
			}
			writeJSON(w, map[string]any{
				"upload":            map[string]any{"url": "https://upload.example.test/put", "method": "PUT", "headers": map[string]string{"X-Test": "yes"}},
				"share":             map[string]string{"public_id": "pub-1", "link": "https://s.example.test/pub-1"},
				"upload_session_id": "upload-1",
				"expires_at":        "2026-07-03T00:00:00Z",
				"link":              "https://s.example.test/pub-1",
			})
		case "/put":
			if r.Method != http.MethodPut || r.Header.Get("X-Test") != "yes" {
				t.Fatalf("put method/header = %s %q", r.Method, r.Header.Get("X-Test"))
			}
			raw, _ := io.ReadAll(r.Body)
			uploaded = string(raw)
			w.WriteHeader(http.StatusOK)
		case "/v1/uploads/upload-1/complete":
			writeJSON(w, map[string]string{"public_id": "pub-1", "status": "ready", "expires_at": "2026-07-03T00:00:00Z"})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})

	client := NewClient("https://api.example.test", "s2s_test")
	client.HTTPClient = handlerClient(handler)
	created, err := client.CreateUpload(t.Context(), UploadCreateRequest{
		FileName:       "a.txt",
		SizeBytes:      5,
		SHA256:         strings.Repeat("a", 64),
		SourceRef:      strings.Repeat("c", 64),
		New:            true,
		RecipientEmail: "recipient@example.test",
		Targets:        []UploadTarget{{TargetDeviceSessionID: "00000000-0000-0000-0000-000000000201", SealedKey: "sealed"}},
	})
	if err != nil {
		t.Fatalf("CreateUpload() error = %v", err)
	}
	if !authSeen || created.Share.PublicID != "pub-1" || created.UploadSessionID != "upload-1" {
		t.Fatalf("created = %+v authSeen=%v", created, authSeen)
	}
	if created.Link != "https://s.example.test/pub-1" || created.Share.Link != "https://s.example.test/pub-1" {
		t.Fatalf("created links = %+v", created)
	}
	if err := client.PutUpload(t.Context(), created.Upload, strings.NewReader("hello"), int64(len("hello"))); err != nil {
		t.Fatalf("PutUpload() error = %v", err)
	}
	if uploaded != "hello" {
		t.Fatalf("uploaded = %q", uploaded)
	}
	completed, err := client.CompleteUpload(t.Context(), created.UploadSessionID)
	if err != nil {
		t.Fatalf("CompleteUpload() error = %v", err)
	}
	if completed.Status != "ready" || completed.PublicID != "pub-1" {
		t.Fatalf("completed = %+v", completed)
	}
}

func TestClientPutUpload429DoesNotRetry(t *testing.T) {
	attempts := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		writeJSON(w, map[string]any{"error": map[string]string{"code": "rate_limited"}})
	})

	client := NewClient("https://api.example.test", "")
	client.HTTPClient = handlerClient(handler)
	err := client.PutUpload(t.Context(), PresignedUpload{URL: "https://upload.example.test/put", Method: http.MethodPut}, strings.NewReader("large"), 5)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %T %v, want APIError", err, err)
	}
	if apiErr.Code != "rate_limited" || !strings.Contains(apiErr.Message, "rate limited by the server") {
		t.Fatalf("api error = %+v", apiErr)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestClientCreateReplaceUpload(t *testing.T) {
	var authSeen bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/shares/pub-1/content" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		authSeen = r.Header.Get("Authorization") == "Bearer s2s_test"
		var req UploadCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode replace upload: %v", err)
		}
		if req.FileName != "a.txt" || req.SizeBytes != 7 || req.ContentClass != "text" || req.Live {
			t.Fatalf("replace request = %+v", req)
		}
		writeJSON(w, map[string]any{
			"upload":            map[string]any{"url": "https://upload.example.test/replace", "method": "PUT"},
			"share":             map[string]string{"public_id": "pub-1"},
			"upload_session_id": "replace-1",
		})
	})

	client := NewClient("https://api.example.test", "s2s_test")
	client.HTTPClient = handlerClient(handler)
	created, err := client.CreateReplaceUpload(t.Context(), "pub-1", UploadCreateRequest{FileName: "a.txt", SizeBytes: 7, ContentClass: "text", SHA256: strings.Repeat("b", 64)})
	if err != nil {
		t.Fatalf("CreateReplaceUpload() error = %v", err)
	}
	if !authSeen || created.Share.PublicID != "pub-1" || created.UploadSessionID != "replace-1" {
		t.Fatalf("created = %+v authSeen=%v", created, authSeen)
	}
}

func TestClientLivePutAndFlush(t *testing.T) {
	var sawPut, sawFlush bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s2s_test" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/v1/shares/pub-1/live":
			sawPut = true
			var req LivePutRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode live put: %v", err)
			}
			if req.Content != "hello" || req.CRC32 != "3610a686" || req.ContentType != "text/plain" {
				t.Fatalf("live put request = %+v", req)
			}
			writeJSON(w, map[string]any{"changed": true, "crc32": req.CRC32, "size": 5, "ttl_seconds": 60})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/shares/pub-1/flush":
			sawFlush = true
			writeJSON(w, map[string]any{"public_id": "pub-1", "version": 2, "sha256": strings.Repeat("a", 64), "size": 5})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	client := NewClient("https://api.example.test", "s2s_test")
	client.HTTPClient = handlerClient(handler)
	put, err := client.PutLive(t.Context(), "pub-1", LivePutRequest{Content: "hello", CRC32: "3610a686", ContentType: "text/plain"})
	if err != nil {
		t.Fatalf("PutLive() error = %v", err)
	}
	if !put.Changed || put.Size != 5 {
		t.Fatalf("put response = %+v", put)
	}
	flush, err := client.FlushShare(t.Context(), "pub-1")
	if err != nil {
		t.Fatalf("FlushShare() error = %v", err)
	}
	if flush.PublicID != "pub-1" || flush.Version != 2 || flush.Size != 5 {
		t.Fatalf("flush response = %+v", flush)
	}
	if !sawPut || !sawFlush {
		t.Fatalf("sawPut=%v sawFlush=%v", sawPut, sawFlush)
	}
}

func TestClientShareAnalytics(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/shares/pub-1/analytics" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer s2s_test" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		writeJSON(w, map[string]any{
			"views":             2,
			"downloads":         1,
			"unique_visitors":   2,
			"first_accessed_at": "2026-07-02T00:00:00Z",
			"last_accessed_at":  "2026-07-02T01:00:00Z",
			"timeline":          []map[string]any{{"date": "2026-07-02", "views": 2, "downloads": 1}},
			"recent":            []map[string]any{{"occurred_at": "2026-07-02T01:00:00Z", "ip": "203.0.113.9", "country": "US", "client": "curl/8", "event_type": "share.downloaded"}},
		})
	})
	client := NewClient("https://api.example.test", "s2s_test")
	client.HTTPClient = handlerClient(handler)

	stats, err := client.ShareAnalytics(t.Context(), "pub-1")
	if err != nil {
		t.Fatalf("ShareAnalytics() error = %v", err)
	}
	if stats.Views != 2 || stats.Downloads != 1 || stats.UniqueVisitors != 2 || len(stats.Recent) != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestCredentialStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "share2us", "credentials.json")
	credential := Credential{APIBase: "https://api.example.test", Token: "s2s_secret", Email: "user@example.test"}

	if err := SaveCredentialAt(path, credential); err != nil {
		t.Fatalf("SaveCredentialAt() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat credential: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 0600", got)
	}

	loaded, err := LoadCredentialAt(path)
	if err != nil {
		t.Fatalf("LoadCredentialAt() error = %v", err)
	}
	credential.SchemaVersion = CredentialSchemaVersion
	if loaded != credential {
		t.Fatalf("loaded = %+v, want %+v", loaded, credential)
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func handlerClient(handler http.Handler) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder.Result(), nil
	})}
}

func stubRateLimitSleep(t *testing.T) func() {
	t.Helper()
	previousSleep := sleepContext
	previousBase := rateLimitBackoffBase
	rateLimitBackoffBase = time.Millisecond
	sleepContext = func(ctx context.Context, d time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	return func() {
		sleepContext = previousSleep
		rateLimitBackoffBase = previousBase
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
