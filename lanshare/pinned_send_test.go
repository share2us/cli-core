package lanshare

import (
	"context"
	"crypto/ed25519"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// A REAL transfer over a real TLS session, proving the construction local-first
// routing depends on (ADR-040): a send authenticated by a PINNED CERTIFICATE and
// no password at all.
//
// Why the pin is enough. probeReceiver takes the certificate fingerprint and the
// device card from the SAME handshake, and cardFromCert only returns a card whose
// signature covers THAT certificate's own public key. So a verified card binds
// the identity key to that exact certificate, and pinning its fingerprint gives
// an authenticated channel to the device that proved the identity.
//
// Why there are three cases. A passwordless sender is accepted only when the
// receiver ITSELF has no password, or the sender proved a trusted identity — and
// the two receivers in this product are not the same shape. The desktop app's
// listener and the daemon run NoPassword; a plain `s2u receive` auto-generates a
// passphrase. Getting that wrong is not theoretical: the CLI shipped advice
// telling users to run `s2u receive`, which refuses this send.
func TestPinnedPasswordlessSend(t *testing.T) {
	for _, tc := range []struct {
		name        string
		noPassword  bool
		trustSender bool
		wrongPin    bool
		wantErr     string
	}{
		{name: "receiver has no password (desktop app and daemon)", noPassword: true},
		{name: "receiver auto-generated a passphrase (plain receive)", wantErr: "requires a password"},
		{name: "auto-passphrase but the sender is trusted", trustSender: true},
		// THE PIN MUST ACTUALLY BE ENFORCED. Without this case the test passes
		// even with PinFingerprint removed entirely -- Send does not require a
		// pin, so "it delivered" proves only that the transfer works, not that
		// the certificate was checked. A wrong pin has to be refused, or the
		// passwordless send would accept any certificate and an on-path attacker
		// on the LAN could take the transfer.
		{name: "a WRONG pin is refused even with no password anywhere", noPassword: true, wrongPin: true, wantErr: "fingerprint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_, senderID, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatalf("sender key: %v", err)
			}
			_, recvID, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatalf("receiver key: %v", err)
			}
			senderPub := senderID.Public().(ed25519.PublicKey)

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			listening := make(chan ListenInfo, 1)
			go func() {
				_, _ = Receive(ctx, ReceiveOptions{
					Bind: "127.0.0.1", NoPassword: tc.noPassword,
					Identity: recvID, DeviceName: "pinned-receiver", DestDir: dir,
					IsTrustedSender: func(k []byte) bool {
						return tc.trustSender && IdentityFingerprint(k) == IdentityFingerprint(senderPub)
					},
					OnListen:  func(l ListenInfo) { listening <- l },
					OnRequest: func(RequestInfo) bool { return true },
				})
			}()

			var li ListenInfo
			select {
			case li = <-listening:
			case <-time.After(10 * time.Second):
				t.Fatal("receiver never came up")
			}

			// Exactly what the router does: scan, then pin the certificate whose
			// card proved the identity.
			peers, err := Scan(ctx, ScanOptions{
				Targets: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
				Port:    li.Port, Timeout: 3 * time.Second,
			})
			if err != nil || len(peers) == 0 {
				t.Fatalf("scan found no receiver (err=%v)", err)
			}
			p := peers[0]
			if p.IdentityFingerprint == "" {
				t.Fatal("peer published no verified device card, so the router could not match it")
			}
			if p.Fingerprint == "" {
				t.Fatal("no certificate fingerprint to pin")
			}

			pin := p.Fingerprint
			if tc.wrongPin {
				pin = strings.Repeat("ab", 32) // a well-formed fingerprint of some other device
			}
			body := strings.NewReader("hello world")
			_, err = Send(ctx, "pinned.txt", int64(body.Len()), false, body, SendOptions{
				Dest:           p.Addr(),
				PinFingerprint: pin, // and deliberately NO Password
				Identity:       senderID,
				SenderName:     "pinned-sender",
			})

			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("pinned passwordless send failed: %v", err)
			}
			got, rerr := os.ReadFile(dir + "/pinned.txt")
			if rerr != nil {
				t.Fatalf("the send reported success but nothing landed: %v", rerr)
			}
			if string(got) != "hello world" {
				t.Fatalf("received %q, want the bytes that were sent", got)
			}
		})
	}
}
