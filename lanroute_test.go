package clicore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/share2us/cli-core/lanshare"
)

func fakeScan(peers []lanshare.ScannedPeer, err error, seen *lanshare.ScanOptions) func(context.Context, lanshare.ScanOptions) ([]lanshare.ScannedPeer, error) {
	return func(_ context.Context, o lanshare.ScanOptions) ([]lanshare.ScannedPeer, error) {
		if seen != nil {
			*seen = o
		}
		return peers, err
	}
}

const (
	fpLaptop = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff0000000011111111"
	fpDesk   = "1111111100000000ffffffffeeeeeeeeddddddddccccccccbbbbbbbbaaaaaaaa"
)

func TestMatchesADeviceThatIsOnThisNetwork(t *testing.T) {
	matches, err := MatchLocalDevices(t.Context(),
		[]DeviceRef{{SessionID: "sess-laptop", LanFingerprint: fpLaptop}},
		MatchOptions{scan: fakeScan([]lanshare.ScannedPeer{
			{Host: "192.168.1.9", Port: 7345, IdentityFingerprint: fpLaptop, Name: "laptop"},
		}, nil, nil)})
	if err != nil {
		t.Fatalf("MatchLocalDevices() error = %v", err)
	}
	if len(matches) != 1 || matches[0].SessionID != "sess-laptop" || matches[0].Peer.Host != "192.168.1.9" {
		t.Fatalf("matches = %+v, want the laptop paired with its peer", matches)
	}
}

// The whole point is that a device NOT on this network routes to the cloud. An
// empty result must be an ordinary answer, never an error.
func TestADeviceThatIsNotHereSimplyDoesNotMatch(t *testing.T) {
	matches, err := MatchLocalDevices(t.Context(),
		[]DeviceRef{{SessionID: "sess-laptop", LanFingerprint: fpLaptop}},
		MatchOptions{scan: fakeScan([]lanshare.ScannedPeer{
			{Host: "192.168.1.22", IdentityFingerprint: fpDesk},
		}, nil, nil)})
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
	if len(matches) != 0 {
		t.Fatalf("matches = %+v, want none", matches)
	}
}

// Matching is on the PROVEN identity fingerprint, never the name. A peer calling
// itself "laptop" is not the account's laptop, and treating it as one would hand
// a file to whoever picked the name.
func TestAMatchingNameIsNotAMatch(t *testing.T) {
	matches, _ := MatchLocalDevices(t.Context(),
		[]DeviceRef{{SessionID: "sess-laptop", LanFingerprint: fpLaptop}},
		MatchOptions{scan: fakeScan([]lanshare.ScannedPeer{
			{Host: "10.0.0.5", Name: "laptop", IdentityFingerprint: fpDesk},
		}, nil, nil)})
	if len(matches) != 0 {
		t.Fatalf("matches = %+v, want none: the name matched but the identity did not", matches)
	}
}

// A peer with no device card cannot be identified, only addressed, and must
// never satisfy a match.
//
// The hazard this guards is EMPTY MATCHING EMPTY: a browser session has no
// fingerprint and a peer without a card has no identity, so an implementation
// that keyed a lookup on both would pair two blanks and route a file to an
// unidentified listener. Both are present here deliberately, alongside one
// device that does match so the scan actually runs.
//
// An earlier version of this test passed even with the code's `fp == ""` guard
// deleted, because the lookup map never holds an empty key — so it was pinning
// nothing. This version fails if either protection is removed.
func TestAPeerWithNoCardNeverMatches(t *testing.T) {
	matches, _ := MatchLocalDevices(t.Context(),
		[]DeviceRef{
			{SessionID: "sess-browser", LanFingerprint: ""}, // nothing to match on
			{SessionID: "sess-laptop", LanFingerprint: fpLaptop},
		},
		MatchOptions{scan: fakeScan([]lanshare.ScannedPeer{
			{Host: "10.0.0.5", Fingerprint: "per-session-cert-fp"}, // no card
			{Host: "192.168.1.9", IdentityFingerprint: fpLaptop},
		}, nil, nil)})
	if len(matches) != 1 {
		t.Fatalf("matches = %+v, want exactly the laptop", matches)
	}
	if matches[0].SessionID != "sess-laptop" {
		t.Fatalf("matched %q, want sess-laptop — the cardless peer was paired with the browser", matches[0].SessionID)
	}
}

// Browsers and older clients have no fingerprint. With nothing matchable in the
// list there is no reason to touch the network at all.
func TestNoMatchableDevicesSkipsTheScanEntirely(t *testing.T) {
	called := false
	_, err := MatchLocalDevices(t.Context(),
		[]DeviceRef{{SessionID: "sess-browser", LanFingerprint: ""}},
		MatchOptions{scan: func(context.Context, lanshare.ScanOptions) ([]lanshare.ScannedPeer, error) {
			called = true
			return nil, nil
		}})
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if called {
		t.Fatal("scanned the network for a list with nothing matchable in it")
	}
}

// A send must never fail because discovery did: the caller falls back to the
// cloud. The error is still returned so it can be logged.
func TestAScanFailureYieldsNoMatchesRatherThanBreakingTheSend(t *testing.T) {
	matches, err := MatchLocalDevices(t.Context(),
		[]DeviceRef{{SessionID: "sess-laptop", LanFingerprint: fpLaptop}},
		MatchOptions{scan: fakeScan(nil, errors.New("network unreachable"), nil)})
	if len(matches) != 0 {
		t.Fatalf("matches = %+v, want none", matches)
	}
	if err == nil {
		t.Fatal("want the scan error returned so a caller can log it")
	}
}

// Reinstalling a client keeps the identity key but creates a NEW session, so one
// fingerprint can name several sessions. One peer must satisfy at most one of
// them, or the caller would send the same file to the same machine twice.
func TestOnePeerSatisfiesOnlyOneSession(t *testing.T) {
	matches, _ := MatchLocalDevices(t.Context(),
		[]DeviceRef{
			{SessionID: "sess-old", LanFingerprint: fpLaptop},
			{SessionID: "sess-new", LanFingerprint: fpLaptop},
		},
		MatchOptions{scan: fakeScan([]lanshare.ScannedPeer{
			{Host: "192.168.1.9", IdentityFingerprint: fpLaptop},
		}, nil, nil)})
	if len(matches) != 1 {
		t.Fatalf("matches = %+v, want exactly one", matches)
	}
}

// Both sides should already be lowercase hex; comparing case-insensitively makes
// a mismatch from a differently-cased source impossible rather than unlikely.
func TestFingerprintComparisonIgnoresCaseAndSpace(t *testing.T) {
	matches, _ := MatchLocalDevices(t.Context(),
		[]DeviceRef{{SessionID: "sess-laptop", LanFingerprint: "  " + upper(fpLaptop) + " "}},
		MatchOptions{scan: fakeScan([]lanshare.ScannedPeer{
			{Host: "192.168.1.9", IdentityFingerprint: fpLaptop},
		}, nil, nil)})
	if len(matches) != 1 {
		t.Fatalf("matches = %+v, want one despite the casing", matches)
	}
}

// The routing decision must not be allowed to cost an unbounded amount of time,
// and a caller that asks for a cheap tailnet-only pass must get one.
func TestOptionsReachTheScan(t *testing.T) {
	var seen lanshare.ScanOptions
	_, _ = MatchLocalDevices(t.Context(),
		[]DeviceRef{{SessionID: "s", LanFingerprint: fpLaptop}},
		MatchOptions{Timeout: 900 * time.Millisecond, SkipLocalSubnets: true, scan: fakeScan(nil, nil, &seen)})
	if seen.Timeout != 900*time.Millisecond || !seen.SkipLocalSubnets {
		t.Fatalf("scan options = %+v, want the caller's timeout and tailnet-only flag", seen)
	}

	seen = lanshare.ScanOptions{}
	_, _ = MatchLocalDevices(t.Context(),
		[]DeviceRef{{SessionID: "s", LanFingerprint: fpLaptop}},
		MatchOptions{scan: fakeScan(nil, nil, &seen)})
	if seen.Timeout != 400*time.Millisecond {
		t.Fatalf("default timeout = %v, want 400ms", seen.Timeout)
	}
}

func upper(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'a' && c <= 'f' {
			out[i] = c - 32
		}
	}
	return string(out)
}
