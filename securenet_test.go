package clicore

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestWrapV1RoundTripAndRefusals(t *testing.T) {
	recipient, _ := NewAccountKey()
	payload := []byte("epoch key bytes .. 32 long .....")
	w, err := WrapV1(recipient.PublicKey().Bytes(), payload, PurposeEpochKeyToAccount)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapV1(recipient, w, PurposeEpochKeyToAccount)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("round trip: %v", err)
	}
	other, _ := NewAccountKey()
	if _, err := UnwrapV1(other, w, PurposeEpochKeyToAccount); err != ErrSecureNetOpen {
		t.Fatalf("other key opened it: %v", err)
	}
	if _, err := UnwrapV1(recipient, w, PurposeAccountKeyToDevice); err != ErrSecureNetOpen {
		t.Fatalf("a wrap for one purpose opened as another: %v", err)
	}
	w.CT[0] ^= 1
	if _, err := UnwrapV1(recipient, w, PurposeEpochKeyToAccount); err != ErrSecureNetOpen {
		t.Fatalf("tampered wrap opened: %v", err)
	}
}

// The CLI's existing NaCl device keys are X25519 keys, so the account key can be wrapped
// to them directly.
func TestDeviceKeysWorkAsX25519(t *testing.T) {
	pair, err := NewDeviceKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := decodeDeviceKey(pair.PrivateKey)
	pub, _ := decodeDeviceKey(pair.PublicKey)
	k, err := DeviceECDHKey(priv)
	if err != nil || !bytes.Equal(k.PublicKey().Bytes(), pub) {
		t.Fatalf("device key is not the same X25519 key: %v", err)
	}
	ak, _ := NewAccountKey()
	akPKCS8, _ := MarshalAccountKey(ak)
	w, _ := WrapV1(pub, akPKCS8, PurposeAccountKeyToDevice)
	back, err := UnwrapV1(k, w, PurposeAccountKeyToDevice)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAccountKey(back)
	if err != nil || !bytes.Equal(parsed.Bytes(), ak.Bytes()) {
		t.Fatalf("account key did not survive PKCS#8: %v", err)
	}
}

func TestRecoveryCodes(t *testing.T) {
	code, err := NewRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.ReplaceAll(code, "-", "")) != 26 || strings.Count(code, "-") != 5 {
		t.Fatalf("code shape: %q", code)
	}
	k1, err := RecoveryKey(code)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := RecoveryKey(strings.ToLower(strings.ReplaceAll(code, "-", " ")))
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("forgiving input failed: %v", err)
	}
	if _, err := RecoveryKey("not-a-code"); err == nil {
		t.Fatal("garbage accepted")
	}
}

// The whole key chain a Secure ShareNet uses, end to end.
func TestSecureShareNetKeyChain(t *testing.T) {
	const net = "6f1c1b7e-0000-4000-8000-000000000001"
	ak, _ := NewAccountKey()
	akPKCS8, _ := MarshalAccountKey(ak)
	code, _ := NewRecoveryCode()
	rk, _ := RecoveryKey(code)
	recWrap, _ := SealSym(rk, akPKCS8, RecoveryAAD("acct-1"))

	ek1, _ := NewDataKey()
	ek2, _ := NewDataKey()
	chain, _ := SealSym(ek2, ek1, EpochChainAAD(net, 1)) // EK2 carries EK1
	ek2Wrap, _ := WrapV1(ak.PublicKey().Bytes(), ek2, PurposeEpochKeyToAccount)

	dk, _ := NewDataKey()
	dkWrap, _ := SealSym(ek1, dk, FileKeyAAD(net, 1)) // a file posted in epoch 1
	nameCT, _ := SealSym(ek1, []byte("plan.pdf"), FileNameAAD(net, 1))

	// A late joiner holds only EK2 (via their account key) and the recovery path.
	rk2, _ := RecoveryKey(code)
	akBack, err := OpenSym(rk2, recWrap, RecoveryAAD("acct-1"))
	if err != nil {
		t.Fatal(err)
	}
	ak2, _ := ParseAccountKey(akBack)
	gotEK2, err := UnwrapV1(ak2, ek2Wrap, PurposeEpochKeyToAccount)
	if err != nil {
		t.Fatal(err)
	}
	gotEK1, err := OpenSym(gotEK2, chain, EpochChainAAD(net, 1))
	if err != nil {
		t.Fatal(err)
	}
	gotDK, err := OpenSym(gotEK1, dkWrap, FileKeyAAD(net, 1))
	if err != nil || !bytes.Equal(gotDK, dk) {
		t.Fatalf("file key: %v", err)
	}
	name, err := OpenSym(gotEK1, nameCT, FileNameAAD(net, 1))
	if err != nil || string(name) != "plan.pdf" {
		t.Fatalf("name: %q %v", name, err)
	}
	// Contexts don't cross: a file key can't be opened as another epoch's or as a name.
	if _, err := OpenSym(gotEK1, dkWrap, FileKeyAAD(net, 2)); err != ErrSecureNetOpen {
		t.Fatal("file key opened under the wrong epoch")
	}
	if _, err := OpenSym(gotEK1, dkWrap, FileNameAAD(net, 1)); err != ErrSecureNetOpen {
		t.Fatal("file key opened as a name")
	}
	if _, err := OpenSym(rk2, recWrap, RecoveryAAD("acct-2")); err != ErrSecureNetOpen {
		t.Fatal("recovery wrap opened for another account")
	}
}

// Pinned vectors the portal's TypeScript implementation must reproduce exactly.
// Regenerate (only when the format deliberately changes): SECURENET_WRITE_VECTORS=1.
type secureNetVectors struct {
	Wrap struct {
		RecipientPrivHex string  `json:"recipient_priv_hex"`
		Purpose          string  `json:"purpose"`
		Wrapped          Wrapped `json:"wrapped"`
		PayloadHex       string  `json:"payload_hex"`
	} `json:"wrap_v1"`
	Sym struct {
		KeyHex       string `json:"key_hex"`
		AAD          string `json:"aad"`
		SealedB64    string `json:"sealed_b64"`
		PlaintextHex string `json:"plaintext_hex"`
	} `json:"sym"`
	Recovery struct {
		Code   string `json:"code"`
		KeyHex string `json:"key_hex"`
	} `json:"recovery"`
	AccountKey struct {
		PKCS8B64  string `json:"pkcs8_b64"`
		PublicHex string `json:"public_hex"`
	} `json:"account_key"`
}

const vectorsPath = "testdata/securenet_vectors.json"

func seeded(label string) *bytes.Reader {
	var out []byte
	for i := 0; len(out) < 256; i++ {
		s := sha256.Sum256([]byte(label + string(rune('a'+i))))
		out = append(out, s[:]...)
	}
	return bytes.NewReader(out)
}

func TestSecureNetVectors(t *testing.T) {
	if os.Getenv("SECURENET_WRITE_VECTORS") == "1" {
		var v secureNetVectors
		recip, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x11}, 32))
		payload := bytes.Repeat([]byte{0x22}, 32)
		w, err := wrapV1(seeded("wrap"), recip.PublicKey().Bytes(), payload, PurposeEpochKeyToAccount)
		if err != nil {
			t.Fatal(err)
		}
		v.Wrap.RecipientPrivHex, v.Wrap.Purpose, v.Wrap.Wrapped, v.Wrap.PayloadHex = hex.EncodeToString(recip.Bytes()), PurposeEpochKeyToAccount, w, hex.EncodeToString(payload)
		key, aad, pt := bytes.Repeat([]byte{0x33}, 32), FileKeyAAD("net-1", 3), []byte("file key ........ 32 bytes long!")
		ct, _ := gcmSeal(key, bytes.Repeat([]byte{0x44}, 12), pt, aad)
		v.Sym.KeyHex, v.Sym.AAD, v.Sym.SealedB64, v.Sym.PlaintextHex = hex.EncodeToString(key), string(aad), base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{0x44}, 12), ct...)), hex.EncodeToString(pt)
		v.Recovery.Code = formatRecovery(bytes.Repeat([]byte{0x55}, 16))
		rk, _ := RecoveryKey(v.Recovery.Code)
		v.Recovery.KeyHex = hex.EncodeToString(rk)
		ak, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x66}, 32))
		p8, _ := MarshalAccountKey(ak)
		v.AccountKey.PKCS8B64, v.AccountKey.PublicHex = base64.StdEncoding.EncodeToString(p8), hex.EncodeToString(ak.PublicKey().Bytes())
		_ = os.MkdirAll("testdata", 0o755)
		b, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(vectorsPath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v secureNetVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	priv, _ := hex.DecodeString(v.Wrap.RecipientPrivHex)
	recip, _ := ecdh.X25519().NewPrivateKey(priv)
	got, err := UnwrapV1(recip, v.Wrap.Wrapped, v.Wrap.Purpose)
	if err != nil || hex.EncodeToString(got) != v.Wrap.PayloadHex {
		t.Fatalf("wrap vector: %v", err)
	}
	key, _ := hex.DecodeString(v.Sym.KeyHex)
	sealed, _ := base64.StdEncoding.DecodeString(v.Sym.SealedB64)
	pt, err := OpenSym(key, sealed, []byte(v.Sym.AAD))
	if err != nil || hex.EncodeToString(pt) != v.Sym.PlaintextHex {
		t.Fatalf("sym vector: %v", err)
	}
	rk, err := RecoveryKey(v.Recovery.Code)
	if err != nil || hex.EncodeToString(rk) != v.Recovery.KeyHex {
		t.Fatalf("recovery vector: %v", err)
	}
	p8, _ := base64.StdEncoding.DecodeString(v.AccountKey.PKCS8B64)
	ak, err := ParseAccountKey(p8)
	if err != nil || hex.EncodeToString(ak.PublicKey().Bytes()) != v.AccountKey.PublicHex {
		t.Fatalf("account key vector: %v", err)
	}
}
