package p2p

import "testing"

// With no out-of-band secret and no explicit Insecure opt-out, a session must
// refuse to connect rather than proceed without SAS peer verification (which
// would let a MITM relay bridge the transfer).
func TestConnectFailsClosedWithoutSecret(t *testing.T) {
	_, _, sErr, rErr := connectPairWithSecrets(t, "", "")
	if sErr == nil && rErr == nil {
		t.Fatal("connect without a peer-verification secret unexpectedly succeeded; want a closed failure")
	}
}
