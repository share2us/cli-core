package clicore

import (
	"encoding/base64"
	"testing"
)

func TestSealedReplyEnvelope(t *testing.T) {
	ek := make([]byte, 32)
	ct, err := SealSym(ek, []byte("all green"), TaskReplyAAD("n-1", 2, "req-1"))
	if err != nil {
		t.Fatal(err)
	}
	env := sealedReplyPrefix + "n-1:2:" + base64.StdEncoding.EncodeToString(ct)
	if !IsSealedReply(env) || IsSealedReply("all green") {
		t.Fatal("IsSealedReply")
	}
	net, epoch, got, err := ParseSealedReply(env)
	if err != nil || net != "n-1" || epoch != 2 {
		t.Fatalf("parse = %q %d %v", net, epoch, err)
	}
	if pt, err := OpenSym(ek, got, TaskReplyAAD("n-1", 2, "req-1")); err != nil || string(pt) != "all green" {
		t.Fatalf("open = %q %v", pt, err)
	}
	if _, err := OpenSym(ek, got, TaskReplyAAD("n-1", 2, "req-2")); err == nil {
		t.Fatal("a reply opened under another request")
	}
	for _, bad := range []string{sealedReplyPrefix + "n-1:x:AAAA", sealedReplyPrefix + "n-1:2", sealedReplyPrefix + "n-1:2:!!"} {
		if _, _, _, err := ParseSealedReply(bad); err == nil {
			t.Fatalf("%q parsed", bad)
		}
	}
}
