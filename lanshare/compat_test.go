// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import "testing"

func TestCompatWith(t *testing.T) {
	const newer = "20261008120000"
	const older = "20261007120000"
	const ancient = "20260101000000" // below MinCompatibleVersion
	for _, tc := range []struct {
		name                    string
		myVer, peerVer, peerMin string
		want                    Compat
	}{
		{"same version", newer, newer, MinCompatibleVersion, CompatOK},
		{"peer is just older", newer, older, MinCompatibleVersion, CompatOlder},
		{"peer below my floor", newer, ancient, MinCompatibleVersion, CompatIncompatible},
		{"i am below the peer's floor", older, newer, "20261101000000", CompatIncompatible},
		{"peer advertises no version", newer, "", "", CompatUnknown},
		{"dev build peer is not blocked", newer, "dev", "", CompatUnknown},
		{"my dev build still reads the peer", "dev", newer, MinCompatibleVersion, CompatOK},
	} {
		if got := CompatWith(tc.myVer, tc.peerVer, tc.peerMin); got != tc.want {
			t.Errorf("%s: CompatWith(%q,%q,%q) = %q, want %q", tc.name, tc.myVer, tc.peerVer, tc.peerMin, got, tc.want)
		}
	}
}

func TestAdvertsCarryMinVersion(t *testing.T) {
	// A version-aware advert publishes this build's floor by default.
	rx := receiverTXT(ListenInfo{Fingerprint: "c", Mode: ModeOpen, AppVersion: "20261008120000"})
	if got := txtValue(rx, "min"); got != MinCompatibleVersion {
		t.Fatalf("default min = %q, want %q", got, MinCompatibleVersion)
	}
	// An explicit floor overrides the default.
	rx = receiverTXT(ListenInfo{Fingerprint: "c", Mode: ModeOpen, AppVersion: "20261008120000", MinPeer: "20261005000000"})
	if got := txtValue(rx, "min"); got != "20261005000000" {
		t.Fatalf("explicit min = %q", got)
	}
	// "-" suppresses the floor; a version-less advert carries none either.
	if got := txtValue(receiverTXT(ListenInfo{Fingerprint: "c", Mode: ModeOpen, AppVersion: "20261008120000", MinPeer: "-"}), "min"); got != "" {
		t.Fatalf("suppressed min = %q, want empty", got)
	}
	if got := txtValue(receiverTXT(ListenInfo{Fingerprint: "c", Mode: ModeOpen}), "min"); got != "" {
		t.Fatalf("version-less min = %q, want empty", got)
	}
}
