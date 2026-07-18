package lanshare

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/schollz/pake/v3"
)

// pakeCurve is the elliptic curve backing the PAKE. P-256 is NIST-standard and
// stdlib-backed (preferred over the library's exotic default for auditability).
const pakeCurve = "p256"

// ekmLabel / ekmLen: TLS 1.3 exporter keying material binds the PAKE to THIS TLS
// session, so a man-in-the-middle running two distinct TLS sessions cannot relay
// the PAKE — the exporters differ and key-confirmation fails.
const (
	ekmLabel = "EXPORTER-share2us-lanshare-v1"
	ekmLen   = 32
)

// exportKeyingMaterial pulls the channel-binding value from a completed TLS conn.
func exportKeyingMaterial(conn *tls.Conn) ([]byte, error) {
	state := conn.ConnectionState()
	ekm, err := state.ExportKeyingMaterial(ekmLabel, nil, ekmLen)
	if err != nil {
		return nil, fmt.Errorf("lanshare: export keying material: %w", err)
	}
	return ekm, nil
}

// confirmMAC is the key-confirmation tag: HMAC(sessionKey, domain || tag || ekm).
func confirmMAC(sessionKey, ekm []byte, tag string) []byte {
	m := hmac.New(sha256.New, sessionKey)
	m.Write([]byte("s2u-lan-confirm-v1\x00"))
	m.Write([]byte(tag))
	m.Write(ekm)
	return m.Sum(nil)
}

// pakeSender runs the sender (role 0) side of the PAKE over rw and verifies the
// receiver's key-confirmation. It returns nil on a matching password.
func pakeSender(rw io.ReadWriter, ekm, password []byte) error {
	p, err := pake.InitCurve(password, 0, pakeCurve)
	if err != nil {
		return fmt.Errorf("lanshare: init pake: %w", err)
	}
	if err := writeFrame(rw, msgPake, p.Bytes()); err != nil {
		return err
	}
	peer, err := readExpect(rw, msgPake)
	if err != nil {
		return err
	}
	if err := p.Update(peer); err != nil {
		return fmt.Errorf("lanshare: pake update: %w", err)
	}
	key, err := p.SessionKey()
	if err != nil {
		return fmt.Errorf("lanshare: pake session key: %w", err)
	}
	// Sender proves first, then verifies the receiver.
	if err := writeFrame(rw, msgConfirm, confirmMAC(key, ekm, "S")); err != nil {
		return err
	}
	if err := readAndVerifyConfirm(rw, key, ekm, "R"); err != nil {
		return err
	}
	return nil
}

// pakeReceiver runs the receiver (role 1) side of the PAKE over rw and verifies
// the sender's key-confirmation. Returns errBadPassword on a wrong password.
func pakeReceiver(rw io.ReadWriter, ekm, password []byte) error {
	p, err := pake.InitCurve(password, 1, pakeCurve)
	if err != nil {
		return fmt.Errorf("lanshare: init pake: %w", err)
	}
	peer, err := readExpect(rw, msgPake)
	if err != nil {
		return err
	}
	if err := p.Update(peer); err != nil {
		return fmt.Errorf("lanshare: pake update: %w", err)
	}
	if err := writeFrame(rw, msgPake, p.Bytes()); err != nil {
		return err
	}
	key, err := p.SessionKey()
	if err != nil {
		return fmt.Errorf("lanshare: pake session key: %w", err)
	}
	// Receiver verifies the sender first, then proves itself.
	if err := readAndVerifyConfirm(rw, key, ekm, "S"); err != nil {
		return err
	}
	if err := writeFrame(rw, msgConfirm, confirmMAC(key, ekm, "R")); err != nil {
		return err
	}
	return nil
}

// errBadPassword indicates key-confirmation failed (wrong password or MITM).
var errBadPassword = errors.New("lanshare: password mismatch (wrong password or man-in-the-middle)")

func readAndVerifyConfirm(r io.Reader, key, ekm []byte, tag string) error {
	typ, got, err := readFrame(r, maxControlFrame)
	if err != nil {
		return err
	}
	if typ == msgError {
		// The peer rejected our confirmation first (wrong password / MITM).
		return errBadPassword
	}
	if typ != msgConfirm {
		return fmt.Errorf("lanshare: expected confirm frame, got %d", typ)
	}
	want := confirmMAC(key, ekm, tag)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return errBadPassword
	}
	return nil
}

// readExpect reads one frame, converting a remote msgError into a descriptive
// error and enforcing the wanted type.
func readExpect(r io.Reader, want byte) ([]byte, error) {
	typ, payload, err := readFrame(r, maxControlFrame)
	if err != nil {
		return nil, err
	}
	if typ == msgError {
		var we wireError
		_ = json.Unmarshal(payload, &we)
		if we.Message == "" {
			we.Message = "remote error"
		}
		return nil, fmt.Errorf("lanshare: remote: %s", we.Message)
	}
	if typ != want {
		return nil, fmt.Errorf("lanshare: unexpected frame type %d (want %d)", typ, want)
	}
	return payload, nil
}
