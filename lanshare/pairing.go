// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
)

// PairingScheme is the URL scheme for a pairing string. A pairing string bundles
// everything a sender needs for a one-scan/one-paste transfer: the address, the
// receiver's cert fingerprint (pinned to defeat MITM), and, in password mode,
// the passphrase (the string is shown on the receiver's own screen, so whoever
// can read it to scan/paste it is already trusted).
const PairingScheme = "s2u"

// PairingInfo is the decoded content of a pairing string.
type PairingInfo struct {
	Host        string
	Port        int
	Fingerprint string
	Password    string
	// AppVersion and MinPeer are the discovered receiver's advertised build stamp
	// and compatibility floor (mDNS "app"/"min" keys), so a sender can check
	// CompatWith before starting. Both "" when the receiver advertised none.
	AppVersion string
	MinPeer    string
}

// Addr returns host:port.
func (p PairingInfo) Addr() string {
	return net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
}

// BuildPairingString encodes a pairing string for a live receiver. host should
// be the address a sender can reach (e.g. the primary LAN / Tailscale IP).
func BuildPairingString(host string, info ListenInfo) string {
	u := url.URL{
		Scheme: PairingScheme,
		Host:   net.JoinHostPort(host, strconv.Itoa(info.Port)),
		Path:   "/join",
	}
	q := url.Values{}
	// "i" is the STABLE identity fingerprint, preferred by senders that
	// understand it so a code survives the receiver regenerating its ephemeral
	// cert. "f" is the per-session cert fingerprint, kept for older senders that
	// pin the certificate directly (same session only).
	if info.IdentityFingerprint != "" {
		q.Set("i", info.IdentityFingerprint)
	}
	if info.Fingerprint != "" {
		q.Set("f", info.Fingerprint)
	}
	if info.Passphrase != "" {
		q.Set("k", info.Passphrase)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// IsPairingString reports whether s looks like a pairing string.
func IsPairingString(s string) bool {
	return len(s) > len(PairingScheme)+3 && s[:len(PairingScheme)+3] == PairingScheme+"://"
}

// ParsePairingString decodes a pairing string produced by BuildPairingString.
func ParsePairingString(s string) (PairingInfo, error) {
	u, err := url.Parse(s)
	if err != nil {
		return PairingInfo{}, fmt.Errorf("lanshare: invalid pairing string: %w", err)
	}
	if u.Scheme != PairingScheme {
		return PairingInfo{}, errors.New("lanshare: not an s2u:// pairing string")
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return PairingInfo{}, fmt.Errorf("lanshare: pairing string missing host:port: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return PairingInfo{}, fmt.Errorf("lanshare: pairing string has invalid port %q", portStr)
	}
	q := u.Query()
	// Prefer the stable identity fingerprint when the code carries one; fall back
	// to the per-session cert fingerprint for codes from older receivers. The
	// sender pins whichever this is, and the TLS layer accepts an identity pin via
	// the certificate's signed card or a cert pin directly.
	fp := q.Get("i")
	if fp == "" {
		fp = q.Get("f")
	}
	return PairingInfo{
		Host:        host,
		Port:        port,
		Fingerprint: fp,
		Password:    q.Get("k"),
	}, nil
}
