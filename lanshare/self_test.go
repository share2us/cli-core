// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import "testing"

// A device listing itself as a nearby device is the bug this guards. The
// fingerprint is the identity the trust model already uses, so it is what the
// exclusion keys on.
func TestSelfFingerprintExcludedWhileAdvertising(t *testing.T) {
	const fp = "AA:BB:CC"
	if isSelfFingerprint(fp) {
		t.Fatal("fingerprint reported as self before anything advertised it")
	}
	release := registerSelf(fp)
	if !isSelfFingerprint(fp) {
		t.Fatal("an advertised fingerprint must be recognised as this device")
	}
	release()
	if isSelfFingerprint(fp) {
		t.Fatal("a closed advert must stop excluding the fingerprint")
	}
}

// A device can advertise twice at once (a receiver plus a broadcast offer). The
// first close must not un-exclude the identity while the second is still up.
func TestSelfFingerprintSurvivesFirstClose(t *testing.T) {
	const fp = "DD:EE:FF"
	releaseA := registerSelf(fp)
	releaseB := registerSelf(fp)
	releaseA()
	if !isSelfFingerprint(fp) {
		t.Fatal("still advertising, so still self")
	}
	releaseB()
	if isSelfFingerprint(fp) {
		t.Fatal("both adverts closed, so no longer self")
	}
}

// Closers can be called more than once; releasing twice must not drop a count
// belonging to another advert.
func TestSelfReleaseIsIdempotent(t *testing.T) {
	const fp = "11:22:33"
	releaseA := registerSelf(fp)
	releaseB := registerSelf(fp)
	releaseA()
	releaseA()
	if !isSelfFingerprint(fp) {
		t.Fatal("a double release must not cancel the other advert")
	}
	releaseB()
	if isSelfFingerprint(fp) {
		t.Fatal("expected release after the last advert closed")
	}
}

// An empty fingerprint means the peer published no identity. It must never be
// treated as self, or every anonymous advert on the network would vanish.
func TestEmptyFingerprintIsNeverSelf(t *testing.T) {
	release := registerSelf("")
	defer release()
	if isSelfFingerprint("") {
		t.Fatal("an empty fingerprint must not match self")
	}
}

// The address backstop catches a second Share2Us process on this machine, which
// publishes a different certificate and so is not caught by fingerprint.
func TestSelfHostMatchesOwnAddresses(t *testing.T) {
	local := map[string]bool{"192.168.15.114": true}
	if !isSelfHost("192.168.15.114", local) {
		t.Fatal("this machine's own address must be recognised as self")
	}
	if !isSelfHost("127.0.0.1", local) {
		t.Fatal("loopback is always self")
	}
	if isSelfHost("192.168.15.115", local) {
		t.Fatal("a different address on the same subnet is a real peer")
	}
	if isSelfHost("", local) {
		t.Fatal("an empty host must not match")
	}
}

// Failing to enumerate interfaces must not empty the nearby list.
func TestSelfHostWithNoLocalAddressesKeepsPeers(t *testing.T) {
	if isSelfHost("192.168.15.114", map[string]bool{}) {
		t.Fatal("with no known local addresses, a peer must be kept")
	}
}
