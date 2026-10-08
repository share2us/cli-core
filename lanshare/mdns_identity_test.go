// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import "testing"

func TestReceiverTXTCarriesIdentityFingerprint(t *testing.T) {
	txt := receiverTXT(ListenInfo{Fingerprint: "cert", Mode: ModeOpen, IdentityFingerprint: "idfp"})
	if txtValue(txt, "id") != "idfp" || txtValue(txt, "f") != "cert" {
		t.Fatalf("txt = %v", txt)
	}
	// No identity set: no id key (older clients).
	if v := txtValue(receiverTXT(ListenInfo{Fingerprint: "c", Mode: ModeOpen}), "id"); v != "" {
		t.Fatalf("unexpected id for identity-less receiver: %q", v)
	}
}

func TestAdvertsCarryAppVersion(t *testing.T) {
	// Receive advert: the app build stamp rides the "app" TXT key so a peer can
	// show which version is on the other end.
	rx := receiverTXT(ListenInfo{Fingerprint: "cert", Mode: ModeOpen, AppVersion: "20261008101506"})
	if got := txtValue(rx, "app"); got != "20261008101506" {
		t.Fatalf("receive advert app = %q, want the build stamp", got)
	}
	// An advertiser that supplies no version adds no key, so older peers are
	// unaffected and the field stays optional.
	if got := txtValue(receiverTXT(ListenInfo{Fingerprint: "c", Mode: ModeOpen}), "app"); got != "" {
		t.Fatalf("unexpected app key for version-less receiver: %q", got)
	}
}
