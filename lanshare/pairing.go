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
	return PairingInfo{
		Host:        host,
		Port:        port,
		Fingerprint: q.Get("f"),
		Password:    q.Get("k"),
	}, nil
}
