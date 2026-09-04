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

// SafetyNumber derives a long, human-comparable number from a device
// fingerprint: five groups of four digits (about 66 bits of the hash), shown
// wherever a device is about to be TRUSTED. Unlike the 6-digit VerifyCode, it
// cannot be matched by grinding certificates: an impersonator would need on the
// order of 10^20 keys. Both ends derive it from the same fingerprint (the other
// device shows its own via `lan id` / Settings), so the user compares two
// numbers, not two hashes. Domain-separated from VerifyCode so the two never
// share bits. Formatted "NNNN NNNN NNNN NNNN NNNN".
func SafetyNumber(fingerprint string) string {
	if fingerprint == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("s2u-safety-number:" + normalizeFingerprint(fingerprint)))
	var groups [5]string
	for i := range groups {
		n := binary.BigEndian.Uint32(sum[i*4:i*4+4]) % 10000
		groups[i] = fmt.Sprintf("%04d", n)
	}
	return groups[0] + " " + groups[1] + " " + groups[2] + " " + groups[3] + " " + groups[4]
}
