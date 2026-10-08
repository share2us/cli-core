// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import "strings"

// MinCompatibleVersion is the oldest Share2Us build (a UTC build stamp,
// YYYYMMDDhhmmss) this build will transfer with. It is advertised as the "min"
// mDNS TXT key so a peer can tell, before a transfer starts, whether the two
// devices can talk. It is a floor for genuine breaking changes, not a "latest"
// nag: it sits well below every current release, so nothing that works today is
// blocked, and it is raised only when a change actually breaks the wire format.
const MinCompatibleVersion = "20260901000000"

// Compat is the compatibility verdict between this device and a peer.
type Compat string

const (
	// CompatOK: the two builds can transfer and neither is behind.
	CompatOK Compat = "ok"
	// CompatOlder: compatible, but the peer is on an older build than this one.
	// Worth a non-blocking "they should update" hint, never a block.
	CompatOlder Compat = "older"
	// CompatIncompatible: one side is below the other's minimum, so a transfer
	// would fail or corrupt. The UI blocks it and says to update.
	CompatIncompatible Compat = "incompatible"
	// CompatUnknown: a version is missing or not a build stamp (an older build
	// that does not advertise one, or a dev build). Treated as OK, never blocked.
	CompatUnknown Compat = "unknown"
)

// CompatWith reports how this device (its own version and MinCompatibleVersion)
// relates to a peer advertising peerVersion and peerMin. Missing or non-stamp
// values are treated as unknown and never block, so a peer too old to advertise
// anything is not refused on a guess.
//
//	myVersion  - this build's stamp (e.g. clicore.FullVersion())
//	peerVersion- the peer's advertised "app" version ("" if none)
//	peerMin    - the peer's advertised "min" version ("" if none)
func CompatWith(myVersion, peerVersion, peerMin string) Compat {
	if !isStamp(peerVersion) {
		return CompatUnknown
	}
	// The peer is older than the floor THIS build still supports.
	if isStamp(peerVersion) && cmpStamp(peerVersion, MinCompatibleVersion) < 0 {
		return CompatIncompatible
	}
	// This build is older than the floor the PEER still supports.
	if isStamp(myVersion) && isStamp(peerMin) && cmpStamp(myVersion, peerMin) < 0 {
		return CompatIncompatible
	}
	if isStamp(myVersion) && cmpStamp(peerVersion, myVersion) < 0 {
		return CompatOlder
	}
	return CompatOK
}

// isStamp reports whether v is a 14-digit UTC build stamp. Dev builds ("dev"),
// semver, and empty strings are not, and must not drive a compatibility block.
func isStamp(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) != 14 {
		return false
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// cmpStamp compares two 14-digit stamps lexicographically, which for equal-length
// all-digit strings is the same as numeric order. Callers gate on isStamp first.
func cmpStamp(a, b string) int { return strings.Compare(a, b) }

// advertisedMin is the "min" TXT value for an advert: the app's explicit MinPeer
// when set, this build's MinCompatibleVersion when the advert carries a version
// at all, and nothing ("-" suppresses it) otherwise. A version-less advertiser
// publishes no floor, exactly as before.
func advertisedMin(info ListenInfo) string {
	switch {
	case info.MinPeer == "-":
		return ""
	case strings.TrimSpace(info.MinPeer) != "":
		return info.MinPeer
	case info.AppVersion != "":
		return MinCompatibleVersion
	default:
		return ""
	}
}
