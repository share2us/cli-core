# Share2Us CLI Core

The shared Go library behind the [Share2Us CLI](https://github.com/share2us/cli).
It holds the logic the command-line client is built on: the API client,
credential storage, end-to-end crypto, QR rendering, local secret scanning,
device identification, and the offline LAN / P2P transfer stack.

This module is published so the CLI builds from source and so the pieces can be
reused, but its primary consumer is the CLI. If you just want the tool, start at
[share2us/cli](https://github.com/share2us/cli).

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
| Crypto | `crypto.go` | End-to-end encryption for device/contact sends. |
| QR | `qr.go` | Renders content and share links as terminal QR codes. |
| Secret scan | `secretscan.go` | Local gitleaks-style scan run before uploads. |
| Content class | `contentclass.go` | Classifies input (text vs binary, size limits) for QR/live decisions. |
| Devices | `device*.go` | Per-OS device identification (Linux/macOS/Windows). |
| Offline transfer | `lanshare/` | Direct LAN/Tailscale/WireGuard transfer (TLS 1.3 + PAKE, mDNS). |
| P2P | `p2p/` | WebRTC peer-to-peer streaming (build-gated). |
| Self-update | `browser.go`, `pending_reseal.go`, `tips.go`, `cache.go` | Update flow, browser launch, cached state, CLI tips. |

## Versioning

The module is tagged (`v0.1.0`, `v0.2.0`, …). Its API tracks what the CLI needs
rather than promising a stable public surface, so pin a version if you depend on
it directly.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Most user-facing behavior is exercised
through the [CLI](https://github.com/share2us/cli); changes here should keep it
building and green.

## License

[GNU General Public License v3.0 only](LICENSE) © 2026 Hassan Khurram

Share2Us clients are free software: you may use, study, share and modify them.
If you distribute a modified version — or a program that links this library —
you must pass on the same freedoms and make the corresponding source available
under the GPL.

Releases published before 2026-09-07 remain under the MIT licence they were
issued with; a licence already granted cannot be withdrawn. The change applies
to this and later versions.
