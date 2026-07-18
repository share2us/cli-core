package clicore

import (
	"fmt"
	"strings"
)

var (
	BuildVersion = "dev"
	Version      = "dev"

	// P2PEnabled gates the direct peer-to-peer streaming commands (`p2p send/recv`
	// and the `stream` alias). Build-time flag, set with:
	//
	//   -ldflags "-X github.com/share2us/cli-core.P2PEnabled=true"
	//
	// It DEFAULTS OFF and is fail-safe: any value other than "true" disables the
	// commands and hides them from the usage text. P2P is also gated server-side
	// (SHARE2US_P2P_ENABLED + the p2p_streaming_enabled plan entitlement), so this
	// is a shipping switch, not a security control — a rebuilt binary cannot turn
	// the feature on by itself.
	P2PEnabled = "false"
)

// P2PStreamingEnabled reports whether this build exposes the P2P commands.
func P2PStreamingEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(P2PEnabled), "true")
}

const (
	DefaultBaseURL   = "share2.us"
	DefaultAPIBase   = "https://api.share2.us"
	DefaultShareBase = "https://s.share2.us"
)

func Usage(command string) string {
	if command == "" {
		command = "share2us"
	}

	usage := fmt.Sprintf(`%s %s

Usage:
  %s login [--host URL] [--no-browser] [--no-input]
  %s config set-base-url <domain>
  %s config set-host <url>
  %s config show
  %s config defaults
  %s config set-default <key> <value>
  %s config unset-default <key>
  %s whoami
  %s logout
  %s signout <device-id|device-name>
  %s update [--host URL] [--version VERSION]
  %s install-agent-tools [--agent codex|claude-code|gemini-cli]
  %s tui
  %s mcp serve
  %s mcp token [--url URL|--staging] [--json]
  %s receive [--watch] [--out PATH]
  %s inbound [disallowed|approvals|auto]
  %s contacts
  %s trust|block|require-approval <email>
  %s untrust|unblock <email>
  %s incoming [approve|reject <id>]
  %s devices
  %s <file> [--expires DUR] [--name NAME] [--password] [--one-time] [--encrypt] [--device ALIAS] [--contact EMAIL] [--email EMAIL] [--to EMAIL] [--max-views N] [--allow-domain DOMAIN] [--deny-domain DOMAIN] [--restrict|--unrestrict] [--new|--fresh] [-l|--live] [-w|--watch] [--allow-secrets|--no-scan] [--qr|--qrl] [--json]
  %s get|-g <url-with-#k> [--key KEY] [--output PATH]
  %s pull <url-or-public-id> [--output PATH]
  %s pull --all [--output DIR]
  %s ls [--json]
  %s stats <serial|public-id>
  %s rm|delete <serial|public-id> [<serial|public-id>...] [--yes]
  %s revoke <serial|public-id>|--all [--yes]
  %s revoke-all [--yes]
  %s pause <serial|public-id>
  %s resume <serial|public-id>
  %s help
  %s version

Environment:
  SHARE2US_BASE_URL          Environment apex domain; api./s. are derived, defaults to %s
  SHARE2US_API_BASE          Advanced API base URL override
  SHARE2US_SHARE_BASE_URL    Advanced display share link base override
  SHARE2US_DEFAULT_EXPIRY    Default upload expiry, defaults to 7d
  SHARE2US_API_TOKEN         Personal access token for non-interactive auth (CI/automation);
                             overrides the saved login. Cannot do device/contact E2E sends.

Upload defaults (config):
  Standing defaults for SAFE upload options, applied when a flag is omitted; an
  explicit flag always overrides (use --no-encrypt / --scan to override a true default).
  %s config defaults                 Show current defaults and their source
  %s config set-default <key> <val>  Set one; keys: expires, reshare, encrypt,
                                     max-views, no-scan, allow-domains, deny-domains
  %s config unset-default <key>      Clear one (falls back to the built-in default)
  Footgun options (password, one-time, recipients, visibility, allow-secrets,
  device/contact) are deliberately NOT defaultable.

Live shares:
  -l, --live     Push text changes to Redis every 3s; flush once on exit
  -w, --watch    Same live pushes, plus durable bucket flushes every 60s

QR codes (a phone camera can read them):
  --qr              Show a QR of the CONTENT itself — a text file, or a quoted
                    text argument (share2us "some text" --qr). Offline, no upload.
                    A binary/oversized file prompts to upload-as-link instead, or
                    cancel (max ~1 KB of text).
  --qrl, --qr-link  Upload as normal, then also show a QR of the share link.

Access controls:
  --one-time                  Single-use: the share dies after one download.
                              OVERRIDES --max-views (any view cap is ignored).
  --max-views N               Allow at most N views (opening the share page) before
                              it stops working. Downloads don't consume views.

Secret scan:
  --allow-secrets, --force    Proceed after local gitleaks findings
  --no-scan                   Skip local secret scanning

Email shares:
  --email EMAIL               Share with a recipient email; repeat or comma-separate.
                              If a single recipient is a contact (a Share2Us user with a
                              device who accepts your shares), it is delivered end-to-end to
                              their device; otherwise it is a recipient-restricted link.
  --to EMAIL                  Alias for --email
  --unrestrict                Let recipients reshare this private share (save it to
                              their own account and share it onward).
  --restrict                  Don't let recipients reshare this private share
                              (the default; overrides your config default).

Device shares:
  --device, -d ALIAS          Send to one of your own logged-in devices with E2E encryption

Contact shares (cross-account device E2E):
  --contact EMAIL             Force E2E to another user's device(s) (fails if not a contact);
                              --email auto-detects contacts, so --contact is only for explicit intent
  inbound MODE                Set your default inbound policy: disallowed|approvals|auto
  trust|block|require-approval <email>   Per-sender override
  incoming [approve|reject <id>]         Review files awaiting your approval

Optional alias:
  alias share=%s
`, command, FullVersion(), command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, command, DefaultBaseURL, command, command, command, command)

	// P2P is hidden entirely unless this build enables it, so a disabled build
	// never advertises a command it will refuse to run.
	if P2PStreamingEnabled() {
		usage = strings.Replace(usage, "\nOptional alias:", fmt.Sprintf(`
Direct P2P streaming (both peers online; bytes are never stored):
  %s p2p send <file> [--relay URL] [--turn URL]
  %s p2p recv <code> [--out PATH]

Optional alias:`, command, command), 1)
	}

	// Offline local/LAN direct share is always available (no account, all tiers).
	usage = strings.Replace(usage, "\nOptional alias:", fmt.Sprintf(`
Offline local/LAN direct share (no account, no cloud — all tiers):
  %s <file|folder> --dest IP[:port] [--password PW]        Send directly to another machine (LAN/Tailscale/WireGuard)
  %s [name] --receive [--password PW|--no-password] [--port N] [--allow-ip IP,...] [--path DIR] [--overwrite]
                                                          Receive a direct transfer
  %s <file|dir> --serve [--bind IP] [--port N] [--qr]      Serve a file/directory over HTTP on your LAN

Optional alias:`, command, command, command), 1)
	return usage
}

func FullVersion() string {
	if build := buildMetadata(BuildVersion); build != "" {
		return build
	}
	if build := buildMetadata(Version); build != "" {
		return build
	}
	return "dev"
}

func buildMetadata(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "dev" || value == "unknown" {
		return ""
	}
	var out strings.Builder
	lastDot := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			out.WriteRune(r)
			lastDot = false
		case r == '.', r == '_', r == ':', r == '/', r == 'T', r == 'Z':
			if out.Len() > 0 && !lastDot {
				out.WriteByte('.')
				lastDot = true
			}
		}
	}
	return strings.Trim(out.String(), ".")
}
