// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import (
	"net"
	"sync"
)

// A device must not appear in its own list of nearby devices.
//
// mDNS is a broadcast protocol: an advert published on a link comes back to
// every listener on that link, including the machine that sent it. So the moment
// a device became discoverable it started finding itself, offering the user a
// "send to" target that loops back to the machine they are sitting at.
//
// The exclusion is keyed on IDENTITY, not address. An address is the wrong key:
// one device holds several (LAN, Tailscale, a VPN), they change, and two devices
// behind different NATs can present the same private address. The certificate
// fingerprint is exactly what the trust model already treats as "who this is",
// so a peer is self when it carries a fingerprint this process is publishing.
//
// Addresses still serve as a backstop for the case identity cannot cover: a
// SECOND Share2Us process on the same machine (a GUI beside the daemon)
// publishes a different certificate, so it is not caught by fingerprint, yet it
// is still this machine and still useless as a send target.

var (
	selfMu sync.Mutex
	// selfFingerprints is a multiset: a fingerprint stays excluded until every
	// advert publishing it has been closed. Counting rather than deleting on the
	// first close keeps the receive advert excluded while a broadcast offer that
	// shares its certificate is still up.
	selfFingerprints = map[string]int{}
)

// registerSelf marks a fingerprint as belonging to this process and returns the
// function that releases it when the advert closes.
func registerSelf(fingerprint string) func() {
	if fingerprint == "" {
		return func() {}
	}
	selfMu.Lock()
	selfFingerprints[fingerprint]++
	selfMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			selfMu.Lock()
			defer selfMu.Unlock()
			if n := selfFingerprints[fingerprint]; n <= 1 {
				delete(selfFingerprints, fingerprint)
			} else {
				selfFingerprints[fingerprint] = n - 1
			}
		})
	}
}

// isSelfFingerprint reports whether this process is publishing that identity.
func isSelfFingerprint(fingerprint string) bool {
	if fingerprint == "" {
		return false
	}
	selfMu.Lock()
	defer selfMu.Unlock()
	return selfFingerprints[fingerprint] > 0
}

// localIPs returns this machine's own addresses. Errors yield an empty set: the
// fingerprint check is the primary guard, and failing to enumerate interfaces
// must not remove real peers from the list.
func localIPs() map[string]bool {
	out := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok {
			out[ipNet.IP.String()] = true
		}
	}
	return out
}

// isSelfHost reports whether host is an address of this machine.
func isSelfHost(host string, local map[string]bool) bool {
	if host == "" {
		return false
	}
	if local[host] {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
