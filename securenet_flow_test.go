package clicore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeKeysAPI is an in-memory stand-in for the key and secure-sharenet endpoints (the
// real ones are covered by share2us-api's DB tests); the bearer token is the account id.
type fakeKeysAPI struct {
	mu       sync.Mutex
	keys     map[string]*fakeAccountKey
	members  []string
	epoch    int
	rotate   bool
	wraps    map[int]map[string]EpochWrap
	chain    map[int][]byte
	recWraps map[string][]byte
}

type fakeAccountKey struct {
	pub     []byte
	devices map[string]*keyDeviceWrap
}

func newFakeKeysAPI() *fakeKeysAPI {
	return &fakeKeysAPI{keys: map[string]*fakeAccountKey{}, wraps: map[int]map[string]EpochWrap{}, chain: map[int][]byte{}, recWraps: map[string][]byte{}}
}

func apiErr(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code}})
}

func (f *fakeKeysAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	acct := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	path := r.URL.Path
	k := f.keys[acct]
	switch {
	case r.Method == "POST" && path == "/v1/keys/enroll":
		var req struct {
			PublicKey    []byte `json:"public_key"`
			RecoveryWrap []byte `json:"recovery_wrap"`
			Device       struct {
				PublicKey []byte  `json:"public_key"`
				Wrap      Wrapped `json:"wrap"`
			} `json:"device"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		wrap := req.Device.Wrap
		f.keys[acct] = &fakeAccountKey{pub: req.PublicKey, devices: map[string]*keyDeviceWrap{
			KeyDeviceID(req.Device.PublicKey): {Approved: true, DevicePublicKey: req.Device.PublicKey, Wrap: &wrap},
		}}
		f.recWraps[acct] = req.RecoveryWrap
		w.WriteHeader(201)
	case k == nil && strings.HasPrefix(path, "/v1/keys"):
		apiErr(w, 404, "not_enrolled")
	case r.Method == "GET" && path == "/v1/keys/recovery":
		_ = json.NewEncoder(w).Encode(map[string]any{"public_key": k.pub, "recovery_wrap": f.recWraps[acct]})
	case r.Method == "POST" && path == "/v1/keys/devices":
		var req struct {
			PublicKey []byte `json:"public_key"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		id := KeyDeviceID(req.PublicKey)
		if k.devices[id] != nil {
			apiErr(w, 409, "device_exists")
			return
		}
		k.devices[id] = &keyDeviceWrap{DevicePublicKey: req.PublicKey}
		w.WriteHeader(201)
	case strings.HasPrefix(path, "/v1/keys/devices/") && strings.HasSuffix(path, "/approve"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/v1/keys/devices/"), "/approve")
		var req struct {
			Wrap Wrapped `json:"wrap"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		d := k.devices[id]
		if d == nil {
			apiErr(w, 404, "not_found")
			return
		}
		if d.Approved {
			apiErr(w, 409, "already_approved")
			return
		}
		d.Approved, d.Wrap = true, &req.Wrap
	case r.Method == "GET" && strings.HasPrefix(path, "/v1/keys/devices/"):
		d := k.devices[strings.TrimPrefix(path, "/v1/keys/devices/")]
		if d == nil {
			apiErr(w, 404, "not_found")
			return
		}
		out := *d
		out.AccountPublicKey = k.pub
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == "GET" && path == "/v1/sharenets/net-1/secure":
		st := SecureState{Secure: true, CurrentEpoch: f.epoch, NeedsRotation: f.rotate}
		for _, m := range f.members {
			sm := SecureMember{AccountID: m}
			if mk := f.keys[m]; mk != nil {
				sm.PublicKey = mk.pub
			}
			st.Members = append(st.Members, sm)
			if f.epoch > 0 && sm.PublicKey != nil {
				if w, ok := f.wraps[f.epoch][m]; !ok || !f.wrapCurrent(m, f.epoch) {
					_ = w
					st.Pending = append(st.Pending, sm)
				}
			}
		}
		for e := 1; e <= f.epoch; e++ {
			if w, ok := f.wraps[e][acct]; ok && f.wrapCurrent(acct, e) {
				st.MyWraps = append(st.MyWraps, w)
			}
			if c := f.chain[e]; c != nil {
				st.Chain = append(st.Chain, ChainLink{Epoch: e, ChainWrap: c})
			}
		}
		_ = json.NewEncoder(w).Encode(st)
	case r.Method == "POST" && (path == "/v1/sharenets/net-1/epochs" || path == "/v1/sharenets/net-1/epoch-wraps"):
		var req struct {
			Epoch     int               `json:"epoch"`
			ChainWrap []byte            `json:"chain_wrap"`
			Sender    []byte            `json:"sender_public_key"`
			Wraps     map[string]wrapTo `json:"wraps"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if !bytes.Equal(req.Sender, k.pub) {
			apiErr(w, 409, "stale_key")
			return
		}
		if path == "/v1/sharenets/net-1/epochs" {
			if req.Epoch != f.epoch+1 {
				apiErr(w, 409, "wrong_epoch")
				return
			}
			f.epoch, f.rotate, f.chain[req.Epoch], f.wraps[req.Epoch] = req.Epoch, false, req.ChainWrap, map[string]EpochWrap{}
		}
		added := 0
		for to, wt := range req.Wraps {
			if !bytes.Equal(wt.RecipientPublicKey, f.keys[to].pub) {
				apiErr(w, 409, "stale_key")
				return
			}
			f.wraps[req.Epoch][to] = EpochWrap{Epoch: req.Epoch, Wrapped: wt.Wrapped, WrappedByAccountID: acct, WrappedByPublicKey: req.Sender}
			added++
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"added": added})
	default:
		apiErr(w, 404, "not_found")
	}
}

// wrapCurrent: a wrap counts only while the recipient still has the key it was made for
// (the server keeps that as recipient_public_key; here, re-checked by opening is too much,
// so a reset clears the account's wraps instead).
func (f *fakeKeysAPI) wrapCurrent(acct string, epoch int) bool {
	_, ok := f.wraps[epoch][acct]
	return ok
}

type fakeDevice struct {
	net  *SecureNet
	keys *Keyring
}

func newFakeDevice(t *testing.T, srv *httptest.Server, acct string, pins *PinStore) fakeDevice {
	t.Helper()
	kp, err := NewDeviceKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := NewKeyring(NewClient(srv.URL, acct), acct, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return fakeDevice{net: &SecureNet{Keys: kr, Pins: pins}, keys: kr}
}

func pins(t *testing.T) *PinStore {
	p, err := OpenPinStore(filepath.Join(t.TempDir(), "pins.json"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSecureSharenetDeviceFlow(t *testing.T) {
	ctx := context.Background()
	api := newFakeKeysAPI()
	srv := httptest.NewServer(api)
	defer srv.Close()
	pinsA, pinsB, pinsC, pinsD := pins(t), pins(t), pins(t), pins(t)
	a1 := newFakeDevice(t, srv, "acct-a", pinsA)

	if _, err := a1.keys.AccountKey(ctx); !errors.Is(err, ErrKeysNotEnrolled) {
		t.Fatalf("before enrolment: %v", err)
	}
	code, err := a1.keys.Enrol(ctx, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	akA, err := a1.keys.AccountKey(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// A second device waits for approval, then holds the same account key.
	a2 := newFakeDevice(t, srv, "acct-a", pinsA)
	if err := a2.keys.RegisterDevice(ctx, "desktop"); err != nil {
		t.Fatal(err)
	}
	if _, err := a2.keys.AccountKey(ctx); !errors.Is(err, ErrDeviceNotApproved) {
		t.Fatalf("unapproved device: %v", err)
	}
	if err := a1.keys.Approve(ctx, a2.keys.DeviceID()); err != nil {
		t.Fatal(err)
	}
	if k, err := a2.keys.AccountKey(ctx); err != nil || !k.Equal(akA) {
		t.Fatalf("approved device: %v", err)
	}

	// A third recovers with the code; a wrong code doesn't open it.
	a3 := newFakeDevice(t, srv, "acct-a", pinsA)
	if err := a3.keys.Recover(ctx, "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-A", "phone"); !errors.Is(err, ErrRecoveryCodeInvalid) {
		t.Fatalf("wrong code: %v", err)
	}
	if err := a3.keys.Recover(ctx, strings.ToLower(code), "phone"); err != nil {
		t.Fatal(err)
	}
	if k, err := a3.keys.AccountKey(ctx); err != nil || !k.Equal(akA) {
		t.Fatalf("recovered device: %v", err)
	}

	// B joins; A's first post creates epoch 1 for both; B opens the file.
	b := newFakeDevice(t, srv, "acct-b", pinsB)
	if _, err := b.keys.Enrol(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	api.members = []string{"acct-a", "acct-b"}
	post, err := a1.net.PreparePost(ctx, "net-1", "plan.pdf")
	if err != nil || post.Epoch != 1 || len(post.FileID) != 22 {
		t.Fatalf("first post: %+v %v", post, err)
	}
	dk, name, err := b.net.OpenFile(ctx, "net-1", 1, post.FileID, post.FileKeyWrap, post.FileNameCT)
	if err != nil || name != "plan.pdf" || !bytes.Equal(dk, post.DataKey) {
		t.Fatalf("B opens: %q %v", name, err)
	}
	if _, _, err := b.net.OpenFile(ctx, "net-1", 1, "BBBBBBBBBBBBBBBBBBBBBB", post.FileKeyWrap, post.FileNameCT); err == nil {
		t.Fatal("a sealed key opened under another file id")
	}

	// C joins late and waits; any holder hands the key over.
	c := newFakeDevice(t, srv, "acct-c", pinsC)
	if _, err := c.keys.Enrol(ctx, "c"); err != nil {
		t.Fatal(err)
	}
	api.members = append(api.members, "acct-c")
	if _, _, err := c.net.OpenFile(ctx, "net-1", 1, post.FileID, post.FileKeyWrap, post.FileNameCT); err == nil {
		t.Fatal("C opened a file before anyone handed over the key")
	}
	if n, skipped, err := b.net.HandOver(ctx, "net-1"); err != nil || n != 1 || len(skipped) != 0 {
		t.Fatalf("hand over: %d %v %v", n, skipped, err)
	}
	if _, name, err := c.net.OpenFile(ctx, "net-1", 1, post.FileID, post.FileKeyWrap, post.FileNameCT); err != nil || name != "plan.pdf" {
		t.Fatalf("C after hand-over: %v", err)
	}

	// B leaves: the next post rotates to epoch 2, chained.
	api.members, api.rotate = []string{"acct-a", "acct-c"}, true
	post2, err := c.net.PreparePost(ctx, "net-1", "notes.txt")
	if err != nil || post2.Epoch != 2 || api.chain[2] == nil {
		t.Fatalf("rotating post: %+v %v", post2, err)
	}
	if _, ok := api.wraps[2]["acct-b"]; ok {
		t.Fatal("the new key was wrapped to the member who left")
	}

	// D joins after the rotation: handed epoch 2 only, reads epoch 1 through the chain.
	d := newFakeDevice(t, srv, "acct-d", pinsD)
	if _, err := d.keys.Enrol(ctx, "d"); err != nil {
		t.Fatal(err)
	}
	api.members = append(api.members, "acct-d")
	if _, _, err := a2.net.HandOver(ctx, "net-1"); err != nil {
		t.Fatal(err)
	}
	if _, name, err := d.net.OpenFile(ctx, "net-1", 1, post.FileID, post.FileKeyWrap, post.FileNameCT); err != nil || name != "plan.pdf" {
		t.Fatalf("D reads history through the chain: %v", err)
	}

	// D's key changes on the server: A won't wrap to it until A trusts it.
	api.keys["acct-d"].pub = append([]byte(nil), akA.PublicKey().Bytes()...) // a key the server chose
	delete(api.wraps[2], "acct-d")
	_, skipped, err := a1.net.HandOver(ctx, "net-1")
	var changed *KeyChangedError
	if err != nil || len(skipped) != 1 || !errors.As(skipped[0], &changed) || changed.AccountID != "acct-d" {
		t.Fatalf("key change not caught: %v %v", skipped, err)
	}
	if err := pinsA.Trust("acct-d", api.keys["acct-d"].pub); err != nil {
		t.Fatal(err)
	}
	if n, skipped, err := a1.net.HandOver(ctx, "net-1"); err != nil || n != 1 || len(skipped) != 0 {
		t.Fatalf("after trusting: %d %v %v", n, skipped, err)
	}
}

func TestKeyFingerprintAndDeviceID(t *testing.T) {
	pub := bytes.Repeat([]byte{1}, 32)
	fp := KeyFingerprint("acct-1", pub)
	if len(fp) != 35 || fp != KeyFingerprint("acct-1", pub) || fp == KeyFingerprint("acct-2", pub) {
		t.Fatalf("fingerprint %q", fp)
	}
	id := KeyDeviceID(pub)
	if len(id) != 24 || id[:2] != "k_" {
		t.Fatalf("device id %q", id)
	}
}

func TestPinStoreTOFU(t *testing.T) {
	p := pins(t)
	k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	if err := p.Check("a", k1); err != nil {
		t.Fatal(err)
	}
	var changed *KeyChangedError
	if err := p.Check("a", k2); !errors.As(err, &changed) {
		t.Fatalf("changed key: %v", err)
	}
	if err := p.Trust("a", k2); err != nil {
		t.Fatal(err)
	}
	if p.Check("a", k1) != nil || p.Check("a", k2) != nil {
		t.Fatal("trusted keys must both stay trusted")
	}
	reopened, err := OpenPinStore(p.path)
	if err != nil || reopened.Check("a", k2) != nil {
		t.Fatalf("pins not persisted: %v", err)
	}
}
