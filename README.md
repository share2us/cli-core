# Share2Us CLI Core

The shared Go library behind the [Share2Us CLI](https://github.com/share2us/cli).
It holds the logic the command-line client is built on: the API client,
credential storage, end-to-end crypto, QR rendering, local secret scanning,
device identification and trust, the background-daemon control channel, and the
offline LAN / P2P transfer stack.

This module is published so the clients build from source and so the pieces can
be reused, but its consumers are the [CLI](https://github.com/share2us/cli) and
the [desktop app](https://github.com/share2us/gui).

**If you are not writing Go, you are in the wrong place.** To use the tool, start
at [docs.share2.us](https://docs.share2.us). To install it, the CLI repository has
the one-liners.

## Install

Requires **Go 1.25+**.

```sh
go get github.com/share2us/cli-core@latest
```

## What's inside

| Area | Files | What it does |
| --- | --- | --- |
| API client | `client.go`, `core.go` | Talks to the Share2Us API; usage/version strings. |
| Config & credentials | `config.go`, `credentials.go`, `localshare_config.go` | Base-URL resolution, upload defaults, saved logins. |
| Crypto | `crypto.go` | End-to-end encryption for device/contact sends, and the framed stream container. See [how it looks from the outside](https://docs.share2.us/guides/encryption/). |
| QR | `qr.go` | Renders content and share links as terminal QR codes. |
| Secret scan | `secretscan.go` | Local gitleaks-style scan run before uploads. |
| Content class | `contentclass.go` | Classifies input (text vs binary, size limits) for QR/live decisions. |
| Devices | `device*.go` | Per-OS device identification (Linux/macOS/Windows). |
| Device trust | `lanid/` | Server-signed trusted-device list (ADR-034) — the client only ever consumes it, never grants trust locally. |
| Daemon control | `daemonctl/` | Control channel for the background daemon (unix socket / Windows named pipe) so the CLI and GUI can find it and hand off the receiver. |
| Agent bridge | `agent.go` | Client for sending a file + prompt to a coding-agent session on another device, sealed to that device's key. |
| Offline transfer | `lanshare/` | Direct LAN/Tailscale/WireGuard transfer (TLS 1.3 + PAKE, mDNS). |
| P2P | `p2p/` | WebRTC peer-to-peer streaming (build-gated). |
| Self-update | `browser.go`, `pending_reseal.go`, `tips.go`, `cache.go` | Update flow, browser launch, cached state, CLI tips. |

## Versioning

The module is tagged, and the tags move often: it tracks what the clients need
rather than promising a stable public surface. **Pin a version** if you depend on
it directly, and read the [changelog](CHANGELOG.md) before moving.

Both clients pin the same version deliberately. A change here that only one of
them picks up is how the two stop behaving identically, which is the single
property this library exists to guarantee.

One consequence worth knowing about: the encrypted stream format carries a
version, every version ever written is still readable, and a file written by a
newer library does **not** open in an older one. Bumping the writer is therefore
a coordinated release of both clients, not a library detail.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Most user-facing behaviour is exercised
through the clients, so a change here should keep both of them building and
green. Build against them with `GOWORK=off` at least once before opening a pull
request: the workspace hides a version mismatch that a released build would hit.

## License

[GNU General Public License v3.0 only](LICENSE) © 2026 Hassan Khurram

Share2Us clients are free software: you may use, study, share and modify them.
If you distribute a modified version — or a program that links this library —
you must pass on the same freedoms and make the corresponding source available
under the GPL.

Releases published before 2026-09-07 remain under the MIT licence they were
issued with; a licence already granted cannot be withdrawn. The change applies
to this and later versions.
