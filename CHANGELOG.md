# Changelog

This library is consumed by the Share2Us CLI and desktop app. A version here
reaches users only when one of those is released.

## v0.41.0 — 2026-09-25

### Added

- **A stable identity for each agent.** `AgentRegisterInput` and `AgentSessionInfo`
  carry `AgentID`: the id `s2u agent bind` creates for an agent and keeps in the
  binding. Session ids change constantly — a new one on every prompt Claude is sent,
  and on every recreation — so nothing that had to outlive a single prompt could be
  keyed to them. Invitations into another owner's project will be granted against
  this id instead.

## v0.40.0 — 2026-09-25

### Added

- **Signed agent hops.** `SignHop`, `VerifyHop` and `VerifyHopFresh`, with a
  per-device Ed25519 signing key (`NewSigningKeyPair`). Until now a prompt sent to
  an agent was sealed so that only the receiving device could read it, but nothing
  proved who had written it: anyone who knew a device's public key could seal a
  prompt to it. A signature lets the server refuse a forged hop before it is
  queued, and lets the receiving machine refuse one even if the server itself was
  the forger. The signature covers the sender, target, prompt, the attachment's
  sealed key, goal, time and a nonce, so a hop cannot be redirected, swapped, moved onto another
  budget or replayed. The byte format is pinned by a golden test vector that the
  server asserts too.

## v0.39.0 — 2026-09-25

### Added

- **Goals.** A goal is a unit of autonomous work with a budget: what is being
  attempted, how it is known to be finished, and what it may spend. `CreateGoal`,
  `ListGoals`, `GetGoal`, `CloseGoal` and `SetGoalState` wrap the new
  `/v1/agent/goals` endpoints, and `AgentInjectInput` gained `GoalID`, which turns
  an injection into a hop counted against that budget instead of a one-off ask.
  Both ceilings — hops and time — are required when opening a goal, because a
  goal without one is unbounded work and there is no sensible default for that.

## v0.38.0 — 2026-09-16

### Fixed

- **Uploads stopped working on the free plan, and this is why.** The library
  guessed a 7-day expiry whenever you did not ask for one. When the free plan's
  maximum retention became shorter than that, every ordinary upload was refused
  by the server for asking to keep the file too long. It now asks for nothing and
  lets the server apply your plan's own default, which is what it should have
  done from the start.
- **Finding a device on a big network.** Working out whether one of your machines
  is on the same network only swept address ranges small enough to walk through,
  so on a large network — which is what Docker and many offices use — it looked
  at nothing at all and concluded the device was elsewhere. It now also asks the
  local network who is announcing themselves and checks those addresses directly.
  What a device announces is only ever used as a place to look: who it actually
  is still has to be proven.

## v0.37.0 — 2026-09-16

### Added

- **This device now tells your account how to recognise it on the local network.**
  When it registers its key, it also sends the fingerprint of its local-network
  identity. Your other machines can then tell that a device in your list is the
  same one they can see on the network in front of them, which is what lets a
  file go straight across rather than up to the cloud and back down. The
  fingerprint is derived from a key this device already announces to every peer
  on that network, so nothing new is revealed by telling your own account about
  it. Nothing behaves differently yet: the routing that uses it comes next.
- **Working out which of your devices is reachable right now.** Given your device
  list, the library can now say which of those machines is answering on this
  network, by matching the identity each one proves it holds. It matches on that
  proof and never on the device's name, because a name is chosen by the device
  itself and two machines can pick the same one. A device that is merely signed in
  does not answer — only one that is actually listening does — so "none of them"
  is an ordinary answer, and callers fall back to sending through the cloud.

## v0.36.0 — 2026-09-11

### Changed

- **The receive help leads with the quick way.** `receive .` takes the one file
  waiting straight into the current folder, and only asks when there is an actual
  choice to make.

## v0.35.0 — 2026-09-11

### Changed

- **The receive help now says that the bare argument is a folder.** It reads as a
  list of alternatives, so `receive 1` looked like "take file 1" when it meant
  "save into a folder called 1". The folder form is listed after the two ways of
  choosing a file, and says outright that a number is refused.

## v0.34.0 — 2026-09-10

### Security

- **An encrypted file now derives its own key.** The stream format gained a
  random salt in its header, and the key that actually encrypts the bytes is
  derived from the share's data key and that salt. Before, every stream used the
  data key directly and told the chunks apart with four random bytes in the
  nonce, which was safe only for as long as no data key was ever used to encrypt
  twice. Nothing did that, but nothing stopped it either, and the failure would
  not have been graceful: two streams that drew the same four bytes would have
  produced the same keystream, which gives away both files and the ability to
  forge. A key can now encrypt as many files as it likes.
- Files encrypted by older versions still open. The format carries its version,
  and every version this library has written is still read.
- **Older versions cannot open files this one writes.** A share encrypted here
  and downloaded by an older CLI or desktop app reports an unsupported format.

## v0.33.0 — 2026-09-10

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
