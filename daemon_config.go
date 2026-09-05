package clicore

import (
	"os"
	"path/filepath"
	"strings"
)

// Approval policies for the background daemon's headless LAN receiver. Trust
// itself is never granted here (ADR-034/ADR-035): these only decide what an
// already-known device's inbound transfer does when no human is at a terminal.
const (
	// ApprovalPolicyStrict rejects everything that is not a trusted+auto device.
	// A trusted+ask or untrusted request is notified and declined. This is the
	// default: a resident receiver must not widen what lands without a human.
	ApprovalPolicyStrict = "strict"
	// ApprovalPolicyNotifyWait notifies for a trusted+ask device and waits for a
	// decision (action buttons or, until those land, a timeout that declines).
	// Untrusted is still rejected. Opt-in.
	ApprovalPolicyNotifyWait = "notify-wait"
)

// DaemonConfig is the per-user configuration for the optional background service
// (`share2us daemon`, ADR-035). It lives as the "daemon" section of Config so the
// CLI and the GUI read one source of truth. Every field is a pointer or defaults
// to a compiled-in value when unset, so an absent section means "all defaults".
type DaemonConfig struct {
	// DestDir is where received files land. "" = the platform Downloads dir.
	DestDir string `json:"dest_dir,omitempty"`
	// LANDiscoverable enables the background LAN receiver. nil = default (on).
	LANDiscoverable *bool `json:"lan_discoverable,omitempty"`
	// Notify enables native desktop notifications. nil = default (on).
	Notify *bool `json:"notify,omitempty"`
	// ApprovalPolicy is one of ApprovalPolicyStrict (default) or
	// ApprovalPolicyNotifyWait.
	ApprovalPolicy string `json:"approval_policy,omitempty"`
}

// DaemonSettings returns the resolved daemon settings with defaults applied, so
// callers never have to nil-check. Off-by-default is a property of whether the
// service is installed, not of these values: once running, LAN and notifications
// default on and approvals default strict.
func (c Config) DaemonSettings() ResolvedDaemon {
	d := ResolvedDaemon{DestDir: "", LANDiscoverable: true, Notify: true, ApprovalPolicy: ApprovalPolicyStrict}
	if c.Daemon == nil {
		return d
	}
	d.DestDir = c.Daemon.DestDir
	if c.Daemon.LANDiscoverable != nil {
		d.LANDiscoverable = *c.Daemon.LANDiscoverable
	}
	if c.Daemon.Notify != nil {
		d.Notify = *c.Daemon.Notify
	}
	if c.Daemon.ApprovalPolicy == ApprovalPolicyNotifyWait {
		d.ApprovalPolicy = ApprovalPolicyNotifyWait
	}
	return d
}

// ResolvedDaemon is DaemonConfig with defaults filled in.
type ResolvedDaemon struct {
	DestDir         string
	LANDiscoverable bool
	Notify          bool
	ApprovalPolicy  string
}

// DaemonRuntimeDir is the per-user runtime directory for the daemon's control
// socket and pid. It prefers XDG_RUNTIME_DIR (systemd's %t, cleaned on logout);
// when that is unset (common over SSH or on minimal sessions) it falls back to a
// "run" dir under the user cache. The directory is created 0700.
func DaemonRuntimeDir() (string, error) {
	base := ""
	if xdg := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); xdg != "" {
		base = filepath.Join(xdg, "share2us")
	} else {
		cache, cerr := CacheBaseDir()
		if cerr != nil {
			return "", cerr
		}
		base = filepath.Join(cache, "run")
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	return base, nil
}

// DaemonSocketPath is the daemon's local control endpoint (unix socket on
// Linux/macOS). Windows uses a named pipe instead (see the daemon package).
func DaemonSocketPath() (string, error) {
	dir, err := DaemonRuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "daemon.sock"), nil
}

// DaemonTokenPath is the per-user token file authenticating control requests. It
// sits next to config.json (0700 dir) and is written 0600.
func DaemonTokenPath() (string, error) {
	cfg, err := ConfigPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfg), "daemon.token"), nil
}
