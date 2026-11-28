package clicore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDMSecretAAD(t *testing.T) {
	got := string(DMSecretAAD("sec-1", "dm-1", "acct-1"))
	if got != "share2us/dm-secret/v1|sec-1|dm-1|acct-1" {
		t.Fatalf("aad = %q", got)
	}
}

func TestDMSecretRoundTripAndRefusals(t *testing.T) {
	ak, _ := NewAccountKey()
	other, _ := NewAccountKey()
	s, err := SealDMSecret(ak.PublicKey().Bytes(), "sec-1", "dm-1", "acct-1", "GitHub token", "ghp_secret")
	if err != nil {
		t.Fatal(err)
	}
	label, value, err := OpenDMSecret(ak, s)
	if err != nil || label != "GitHub token" || value != "ghp_secret" {
		t.Fatalf("open = %q %q %v", label, value, err)
	}

	cases := map[string]func(DMSecret) DMSecret{
		"other id":      func(s DMSecret) DMSecret { s.ID = "sec-2"; return s },
		"other dm":      func(s DMSecret) DMSecret { s.DMID = "dm-2"; return s },
		"other account": func(s DMSecret) DMSecret { s.RecipientAccountID = "acct-2"; return s },
		"other sender": func(s DMSecret) DMSecret {
			k, _ := NewAccountKey()
			s.SenderPub = k.PublicKey().Bytes()
			return s
		},
		"tampered ct": func(s DMSecret) DMSecret {
			s.CT = append([]byte(nil), s.CT...)
			s.CT[0] ^= 1
			return s
		},
		"short nonce": func(s DMSecret) DMSecret { s.Nonce = s.Nonce[:8]; return s },
	}
	for name, mut := range cases {
		if _, _, err := OpenDMSecret(ak, mut(s)); !errors.Is(err, ErrSecureNetOpen) {
			t.Errorf("%s: err = %v, want ErrSecureNetOpen", name, err)
		}
	}
	if _, _, err := OpenDMSecret(other, s); !errors.Is(err, ErrSecureNetOpen) {
		t.Errorf("wrong key: err = %v", err)
	}
	// An envelope made for another purpose doesn't open as a DM secret.
	sender, _ := NewAccountKey()
	w, _ := WrapV1(sender, ak.PublicKey().Bytes(), []byte(`{"v":1,"label":"x","value":"y"}`), PurposeEpochKeyToAccount, DMSecretAAD("sec-1", "dm-1", "acct-1"))
	wrongPurpose := DMSecret{ID: "sec-1", DMID: "dm-1", RecipientAccountID: "acct-1", SenderPub: sender.PublicKey().Bytes(), Eph: w.Eph, Nonce: w.Nonce, CT: w.CT}
	if _, _, err := OpenDMSecret(ak, wrongPurpose); !errors.Is(err, ErrSecureNetOpen) {
		t.Errorf("wrong purpose: err = %v", err)
	}
	removed := s
	removed.Eph, removed.Nonce, removed.CT = nil, nil, nil
	if _, _, err := OpenDMSecret(ak, removed); !errors.Is(err, ErrDMSecretRemoved) {
		t.Errorf("removed: err = %v", err)
	}
}

func TestOpenDMSecretPayloadVersion(t *testing.T) {
	ak, _ := NewAccountKey()
	sender, _ := NewAccountKey()
	for _, pt := range []string{`{"v":2,"label":"x","value":"y"}`, `not json`} {
		w, _ := WrapV1(sender, ak.PublicKey().Bytes(), []byte(pt), PurposeDMSecret, DMSecretAAD("s", "d", "a"))
		s := DMSecret{ID: "s", DMID: "d", RecipientAccountID: "a", SenderPub: sender.PublicKey().Bytes(), Eph: w.Eph, Nonce: w.Nonce, CT: w.CT}
		if _, _, err := OpenDMSecret(ak, s); err == nil {
			t.Errorf("payload %q opened", pt)
		}
	}
}

func TestSealDMSecretSizeLimit(t *testing.T) {
	ak, _ := NewAccountKey()
	if _, err := SealDMSecret(ak.PublicKey().Bytes(), "s", "d", "a", "big", strings.Repeat("x", MaxDMSecretPayload)); err == nil {
		t.Fatal("oversized secret sealed")
	}
}

func TestGetDMSecret(t *testing.T) {
	ak, _ := NewAccountKey()
	sealed, _ := SealDMSecret(ak.PublicKey().Bytes(), "sec-1", "dm-1", "acct-1", "db password", "hunter2")
	sealed.SharenetID = "net-1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/secrets/sec-1" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not_found"}`))
			return
		}
		// The wire shape: byte fields as standard base64 strings.
		_ = json.NewEncoder(w).Encode(sealed)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "s2s_test")
	got, err := c.GetDMSecret(context.Background(), "sec-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.SharenetID != "net-1" || got.Label != "db password" || len(got.SenderPub) != 32 || len(got.Nonce) != 12 {
		t.Fatalf("got = %+v", got)
	}
	if _, value, err := OpenDMSecret(ak, got); err != nil || value != "hunter2" {
		t.Fatalf("open = %q %v", value, err)
	}
	var apiErr *APIError
	if _, err := c.GetDMSecret(context.Background(), "nope"); !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound {
		t.Fatalf("missing: err = %v", err)
	}
}
