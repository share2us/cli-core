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
