// Package lanshare implements Share2Us's offline, account-free, direct
// peer-to-peer file transfer over a LAN / Tailscale / WireGuard / any reachable
// IP. It never touches the Share2Us cloud, relay, or TURN — this is the "actual
// guest mode": two machines, one TLS 1.3 connection, no login.
//
// Security model (layered):
//   - Transport is always TLS 1.3 (confidentiality + integrity + forward secrecy).
//   - Password auth: a PAKE (schollz/pake) bound to the TLS exporter keying
//     material — MITM-proof and immune to offline dictionary attack even on a
//     weak password.
//   - QR / trusted-peer auth: the sender pins the receiver's self-signed cert
//     SHA-256 fingerprint (delivered out-of-band via the QR / saved config).
//   - --allow-ip: source-IP allowlist (auth by network identity); TLS still
//     provides confidentiality. Active on-path MITM on an untrusted L2 is out of
//     scope for this mode (callers are warned).
package lanshare

import (
	"fmt"
	"strings"

	"github.com/sethvargo/go-diceware/diceware"
)

// DefaultPassphraseWords is the number of diceware words in an auto-generated
// receive passphrase. Ten EFF-large-list words is ~129 bits of entropy, which
// makes the PAKE's password path immune to any offline guessing.
const DefaultPassphraseWords = 10

// GeneratePassphrase returns a space-free, hyphen-joined diceware passphrase of
// n words drawn from the EFF large word list using crypto/rand. It is used when
// a receiver is opened without an explicit -p/--password and without -np.
func GeneratePassphrase(n int) (string, error) {
	if n <= 0 {
		n = DefaultPassphraseWords
	}
	words, err := diceware.Generate(n)
	if err != nil {
		return "", fmt.Errorf("generate passphrase: %w", err)
	}
	return strings.Join(words, "-"), nil
}
