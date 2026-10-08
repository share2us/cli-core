package lanshare

import (
	"context"
	"crypto/ed25519"
	"os"
	"strings"
	"testing"
	"time"
)

// Pinning the STABLE identity fingerprint must authenticate the device even
// though that value never equals the ephemeral certificate's fingerprint. This is
// the fix for "peer certificate fingerprint mismatch (possible MITM)" after a
// receiver regenerated its cert: the signed card binds the ephemeral cert to the
// identity, so an identity pin keeps working. A random identity pin must still be
// refused.
func TestIdentityPinnedSend(t *testing.T) {
	for _, tc := range []struct {
		name     string
		wrongPin bool
		wantErr  string
	}{
		{name: "identity pin authenticates via the signed card"},
		{name: "a wrong identity pin is refused", wrongPin: true, wantErr: "fingerprint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			recvPub, recvID, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatalf("receiver key: %v", err)
			}
			_, senderID, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatalf("sender key: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			listening := make(chan ListenInfo, 1)
			go func() {
				_, _ = Receive(ctx, ReceiveOptions{
					Bind: "127.0.0.1", NoPassword: true,
					Identity: recvID, DeviceName: "id-receiver", DestDir: dir,
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
			if li.IdentityFingerprint == "" || li.IdentityFingerprint != IdentityFingerprint(recvPub) {
				t.Fatalf("receiver did not expose its stable identity fingerprint: %q", li.IdentityFingerprint)
			}
			// Deliberately pin the IDENTITY fp, which differs from the cert fp.
			if li.IdentityFingerprint == li.Fingerprint {
				t.Fatal("identity and cert fingerprints should differ (cert is ephemeral)")
			}

			pin := li.IdentityFingerprint
			if tc.wrongPin {
				pin = strings.Repeat("ab", 32)
			}
			body := strings.NewReader("over lan")
			_, err = Send(ctx, "id.txt", int64(body.Len()), false, body, SendOptions{
				Dest:           li.BindAddr + ":" + itoa(li.Port),
				PinFingerprint: pin,
				Identity:       senderID,
				SenderName:     "id-sender",
			})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("identity-pinned send failed: %v", err)
			}
			if got, rerr := os.ReadFile(dir + "/id.txt"); rerr != nil || string(got) != "over lan" {
				t.Fatalf("delivered bytes = %q (err %v), want %q", got, rerr, "over lan")
			}
		})
	}
}

// The pairing string carries both fingerprints and a reader prefers the stable
// identity one, so a shared code pins the device, not the session.
func TestPairingStringPrefersIdentityFingerprint(t *testing.T) {
	s := BuildPairingString("192.168.1.5", ListenInfo{
		Port: 4455, Fingerprint: "cert00", IdentityFingerprint: "id9999",
	})
	pi, err := ParsePairingString(s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pi.Fingerprint != "id9999" {
		t.Fatalf("pairing fingerprint = %q, want the identity fp id9999", pi.Fingerprint)
	}
	// A legacy code with only the cert fp still parses to that.
	legacy, _ := ParsePairingString(BuildPairingString("192.168.1.5", ListenInfo{Port: 4455, Fingerprint: "certONLY"}))
	if legacy.Fingerprint != "certONLY" {
		t.Fatalf("legacy pairing fingerprint = %q, want certONLY", legacy.Fingerprint)
	}
}
