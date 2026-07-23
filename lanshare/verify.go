package lanshare

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// VerifyCode derives a short, human-comparable 6-digit numeric code from a
// receiver's certificate fingerprint. Both ends compute the SAME code from the
// same certificate, so a sender can confirm — by comparing the code shown on the
// receiver's own screen — that a device advertised over (unauthenticated) mDNS is
// the real one and not an impersonator, whose different certificate yields a
// different code. Formatted "NNN NNN".
//
// Six digits is a deliberate usability choice: it stops casual impersonation and
// sending to the wrong device, layered under the receiver's per-transfer
// approval. It is NOT a full safety-number compare — a determined attacker could
// grind a certificate whose fingerprint matches a target's 6-digit code.
func VerifyCode(fingerprint string) string {
	if fingerprint == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalizeFingerprint(fingerprint)))
	n := binary.BigEndian.Uint64(sum[:8]) % 1_000_000
	return fmt.Sprintf("%03d %03d", n/1000, n%1000)
}
