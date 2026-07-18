# Contributing to Share2Us CLI Core

Thanks for your interest in improving `cli-core` — the shared library behind the
[Share2Us CLI](https://github.com/share2us/cli). Bug reports and pull requests
are welcome.

Most user-facing behavior is driven by the CLI, so an improvement here usually
lands alongside a change there. When in doubt about where something belongs, the
rule of thumb is: reusable logic (client, crypto, config, transfer) lives in
`cli-core`; argument parsing and command wiring live in the CLI.

## Security issues

Do **not** open a public issue for a vulnerability — several packages here handle
credentials, encryption, and secret scanning. Email **support@share2.us** with
the details and we'll coordinate a fix and disclosure.

## Development

Requires **Go 1.25+**.

```sh
git clone https://github.com/share2us/cli-core
cd cli-core
go test ./...              # tests
go vet ./...               # vet
gofmt -l .                 # formatting (should print nothing)
```

To develop against a local CLI checkout, add a temporary `replace` in the CLI's
`go.mod` pointing at your `cli-core` working copy (remove it before committing).

### Notes for specific areas

- **Crypto and credentials** (`crypto.go`, `credentials.go`): changes must keep
  existing stored credentials readable — bump `CredentialSchemaVersion` and add a
  migration path rather than breaking older files.
- **Secret scan** (`secretscan.go`): the fixtures in the test files are
  intentionally-fake sample secrets used to prove detection. Never add a real
  secret, even as a test case.
- **Transfer** (`lanshare/`, `p2p/`): keep the TLS 1.3 + PAKE handshake intact;
  don't weaken the authenticated path for convenience.

## Pull requests

- Keep changes focused and add tests for behavior you change.
- Run `gofmt`, `go vet`, and `go test ./...` before pushing.
- Match the commit style in the log: `scope: short summary`
  (e.g. `lanshare: friendlier auth errors`).
- If you change the API the CLI depends on, make sure the CLI still builds; the
  module is tagged, so coordinate a version bump for breaking changes.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE.md).
