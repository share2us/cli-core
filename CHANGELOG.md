# Changelog

This library is consumed by the Share2Us CLI and desktop app. A version here
reaches users only when one of those is released.

## v0.33.0 — unreleased

The 2026-09-09 security audit, plus the shared pieces of private uploads and the
one receive setting.

### Security

- **LAN prompts no longer carry attacker text.** A sender chooses its own display
  name and the file name, and both went to the approval prompt raw, so terminal
  escapes could rewrite the line a person was about to approve. Every peer-chosen
  name is cleaned before it reaches a prompt, a device list, or the account's
  trust list, and the destination path is resolved before the prompt so the name
  approved is the name that lands.
- **The trusted-device cache is pinned to keys this build knows**, and bound to
  the account that is logged in. It used to be verified against a public key read
  from the same file, so any local process could write a self-signed list with
  its own device on "auto" and bypass the ADR-034 gate offline. The production
  and staging signing keys are compiled in; `SHARE2US_TRUST_KEYS` adds one for a
  self-hosted server.
- **Peer-to-peer verification is no longer defeatable by reflection.** Both sides
  computed the same short-authentication MAC and each accepted a MAC equal to its
  own, so a malicious relay could bounce each side's message back and sit in the
  middle. The MAC now carries the sender's role.
- **Retained content keys are handled as the secrets they are.** They moved to
  the directory the credential lives in (on Windows they were in a different
  place entirely), an expired key is now removed from the file rather than merely
  ignored on read, and logging out deletes them.
- **A transfer has a deadline again.** It was cleared once bytes started, leaving
  only a per-frame timeout, so a peer could send one frame a minute and hold the
  connection indefinitely.
- **The pull side checks what it is told.** `discover --download` took the size
  from the broadcaster with none of the checks the push side applies; it now
  refuses an implausible size, one raised after approval, and a transfer that
  will not fit on the disk.
- **The device identity is saved safely**, through an exclusive temporary file
  and a rename, with the error reported. A device that could not save its key
  used to generate a new one every run and appear as a stranger to every peer
  that had trusted it.
- Dependencies pinned to the first version that fixes each advisory:
  `golang.org/x/net` v0.56.0 (GO-2026-5942, a panic a remote peer could trigger)
  and `golang.org/x/text` v0.39.0 (GO-2026-5970).

### Added

- `UniquePath`, so a file name chosen by a sender never replaces something
  already on disk.
- Private uploads: a share with no recipients, and an owner-minted unlock token
  for reading your own private share back.
- One receive setting (`receive.dir`, `receive.auto`) that every receiver reads,
  so the CLI, the daemon and the desktop app cannot disagree about where an
  arriving file goes.
