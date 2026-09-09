package p2p

import (
	"bytes"
	"testing"
)

// §AJ #9. Both peers used to compute the SAME SAS MAC and each accepted a MAC
// equal to its own, so a relay that simply REFLECTED each side's message back
// passed verification on both sides and sat in the middle with plaintext,
// never knowing the pairing code. The value a peer must receive has to be one
// it cannot produce itself.
func TestSASMACsDifferByRoleSoAReflectionFails(t *testing.T) {
	const secret = "correct-horse-battery"
	binding := channelBinding("AA:BB", "CC:DD")

	senderMine, senderExpects := sasRoleTags(Sender)
	recvMine, recvExpects := sasRoleTags(Receiver)

	senderSends := sasMAC(secret, binding, senderMine)
	recvSends := sasMAC(secret, binding, recvMine)

	if bytes.Equal(senderSends, recvSends) {
		t.Fatal("both roles produce the same MAC: a relay can reflect it and pass")
	}
	// An honest exchange still verifies in both directions.
	if !bytes.Equal(recvSends, sasMAC(secret, binding, senderExpects)) {
		t.Fatal("the sender does not accept the receiver's genuine MAC")
	}
	if !bytes.Equal(senderSends, sasMAC(secret, binding, recvExpects)) {
		t.Fatal("the receiver does not accept the sender's genuine MAC")
	}
	// The reflection attack: each side is handed back what it sent.
	if bytes.Equal(senderSends, sasMAC(secret, binding, senderExpects)) {
		t.Fatal("the sender accepts its OWN MAC back: reflection still works")
	}
	if bytes.Equal(recvSends, sasMAC(secret, binding, recvExpects)) {
		t.Fatal("the receiver accepts its OWN MAC back: reflection still works")
	}
}

// The binding is canonical (order-independent) so both peers derive the same
// one, and a different fingerprint pair -- which is what a DTLS-terminating
// relay produces -- gives a different MAC.
func TestChannelBindingIsCanonicalAndBindsBothFingerprints(t *testing.T) {
	if channelBinding("AA", "BB") != channelBinding("BB", "AA") {
		t.Fatal("binding is not canonical")
	}
	const secret = "s"
	honest := sasMAC(secret, channelBinding("AA", "BB"), "S")
	mitm := sasMAC(secret, channelBinding("AA", "ZZ"), "S")
	if bytes.Equal(honest, mitm) {
		t.Fatal("a different fingerprint pair produced the same MAC")
	}
}

func TestSASRoleTagsAreOpposite(t *testing.T) {
	sMine, sTheirs := sasRoleTags(Sender)
	rMine, rTheirs := sasRoleTags(Receiver)
	if sMine != rTheirs || rMine != sTheirs || sMine == rMine {
		t.Fatalf("tags do not pair up: sender=(%s,%s) receiver=(%s,%s)", sMine, sTheirs, rMine, rTheirs)
	}
}
