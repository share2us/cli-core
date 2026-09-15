// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"context"
	"strings"
	"time"

	"github.com/share2us/cli-core/lanshare"
)

// Local-first routing: decide, at send time, whether one of the account's own
// devices is ALSO reachable on this network, so the file can go straight across
// instead of up to the cloud and back down.
//
// Until now nothing could make that decision. A device session is a server-side
// row the account owns; a LAN peer is discovered by its device card, which
// carries a persistent identity key and a self-chosen name. The two had nothing
// in common to match on, so "send to my laptop" uploaded even with the laptop in
// the same room. device_sessions.lan_fingerprint is the join, and this is the
// code that uses it.
//
// WHY THIS LIVES IN cli-core rather than in each client: the CLI and the desktop
// app must make the SAME decision, and a routing rule implemented twice is a
// routing rule that diverges. The clients supply their device list and act on the
// answer; the matching is here, with tests.

// DeviceRef is the minimum a caller must know about one of its own devices to
// ask whether it is reachable locally.
type DeviceRef struct {
	// SessionID identifies the device server-side; it is echoed back in the match
	// so the caller can pair the answer with whatever else it holds.
	SessionID string
	// LanFingerprint is the device's stable LAN identity fingerprint, from the
	// device list. Empty means "not matchable" and is not an error.
	LanFingerprint string
}

// LocalMatch pairs one of the account's devices with the peer answering for it
// on this network right now.
type LocalMatch struct {
	SessionID string
	Peer      lanshare.ScannedPeer
}

// MatchOptions bounds the discovery a routing decision is allowed to cost.
type MatchOptions struct {
	// Timeout per host for dial + handshake. Default 400ms, matching the desktop
	// app's routine discovery pass.
	Timeout time.Duration
	// SkipLocalSubnets probes only tailnet peers. Useful for a cheap pass when a
	// subnet sweep would be too slow or too noisy for the moment.
	SkipLocalSubnets bool
	// scan is swapped in tests. Nil uses lanshare.Scan.
	scan func(context.Context, lanshare.ScanOptions) ([]lanshare.ScannedPeer, error)
}

// MatchLocalDevices reports which of devices are reachable directly right now.
//
// A device appears in the result ONLY when a peer on this network presented a
// verified device card whose stable identity fingerprint equals that device's
// lan_fingerprint. That is a cryptographic match on a key the peer proved it
// holds, not a match on a name: names are self-chosen and collide, which is
// exactly why the fingerprint exists.
//
// AN EMPTY RESULT IS THE NORMAL ANSWER, not a failure. A device is only
// discoverable while it is actually listening for a transfer — the desktop app
// with "discoverable on local network" on, or the daemon running. A laptop that
// is merely signed in does not answer a probe, and the correct behaviour then is
// to fall back to the cloud, not to report an error at the user.
//
// A scan error is likewise reported as "no local match" rather than propagated:
// a send must never fail because discovery did. The error is returned alongside
// the (empty) matches so a caller that wants to log it can, and callers that just
// want a routing answer can ignore it.
func MatchLocalDevices(ctx context.Context, devices []DeviceRef, opts MatchOptions) ([]LocalMatch, error) {
	// Build the lookup first: if nothing in the list can be matched at all
	// (browsers, older clients), there is no reason to touch the network.
	wanted := make(map[string]string, len(devices)) // fingerprint -> session id
	for _, d := range devices {
		fp := normaliseFingerprint(d.LanFingerprint)
		if fp == "" || d.SessionID == "" {
			continue
		}
		// First writer wins. Reinstalling a client keeps the identity key while
		// creating a NEW session, so one fingerprint can name several sessions;
		// the caller passes the ones it cares about and any of them is a correct
		// answer for "this machine is here".
		if _, seen := wanted[fp]; !seen {
			wanted[fp] = d.SessionID
		}
	}
	if len(wanted) == 0 {
		return nil, nil
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}
	scan := opts.scan
	if scan == nil {
		scan = lanshare.Scan
	}

	peers, err := scan(ctx, lanshare.ScanOptions{
		Timeout:          timeout,
		SkipLocalSubnets: opts.SkipLocalSubnets,
	})
	if err != nil {
		return nil, err
	}

	matches := make([]LocalMatch, 0, len(peers))
	claimed := make(map[string]bool, len(peers))
	for _, p := range peers {
		fp := normaliseFingerprint(p.IdentityFingerprint)
		// A peer with no card cannot be identified, only addressed. Redundant
		// with the empty-fingerprint skip when the lookup is built — and kept
		// deliberately, because the hazard is EMPTY MATCHING EMPTY and either
		// guard alone prevents it. Removing both is what breaks it, which is
		// exactly what TestAPeerWithNoCardNeverMatches asserts.
		if fp == "" {
			continue
		}
		session, ok := wanted[fp]
		if !ok || claimed[session] {
			continue
		}
		claimed[session] = true
		matches = append(matches, LocalMatch{SessionID: session, Peer: p})
	}
	return matches, nil
}

// normaliseFingerprint lowercases and trims, so a value that arrived from a
// slightly different source still compares equal. Both sides are expected to be
// lowercase hex already; this makes a mismatch impossible rather than unlikely.
func normaliseFingerprint(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}
