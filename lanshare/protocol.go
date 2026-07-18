package lanshare

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Wire protocol (all frames sent over the established TLS 1.3 connection):
//
//	[1 byte type][4 byte big-endian length][length bytes payload]
//
// Control payloads are JSON and capped at maxControlFrame. File data is streamed
// as msgData frames of up to chunkBytes, terminated by a zero-length msgEOF.
const (
	protocolVersion = 1

	msgHello  byte = 1 // sender -> receiver: transfer intent + auth mode
	msgPake   byte = 2 // both ways: raw PAKE handshake bytes
	msgConfirm byte = 3 // both ways: PAKE key-confirmation MAC (EKM-bound)
	msgAccept byte = 4 // receiver -> sender: accept/reject decision
	msgData   byte = 5 // sender -> receiver: a file chunk
	msgEOF    byte = 6 // sender -> receiver: end of stream (zero length)
	msgDone   byte = 7 // receiver -> sender: completion result
	msgError  byte = 8 // either way: fatal error, connection closes after

	// maxControlFrame caps any JSON/handshake control frame. Oversized frames
	// are rejected before allocation to bound memory on the open port.
	maxControlFrame = 64 * 1024
	// chunkBytes is the file-streaming chunk size.
	chunkBytes = 64 * 1024
	// maxDataFrame caps a single data frame (chunk + slack).
	maxDataFrame = chunkBytes + 4096
)

// hello is the sender's opening declaration. HasPassword tells the receiver
// whether the sender will run the PAKE; the receiver rejects a mismatch against
// its own policy (password required vs not expecting one).
type hello struct {
	Version     int    `json:"version"`
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	IsDir       bool   `json:"is_dir"`
	HasPassword bool   `json:"has_password"`
}

// accept is the receiver's decision after auth + local checks.
type accept struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// done is the receiver's completion report.
type done struct {
	OK     bool   `json:"ok"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// wireError carries a fatal, human-readable reason across the connection.
type wireError struct {
	Message string `json:"message"`
}

// writeFrame writes one typed, length-prefixed frame.
func writeFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > int(^uint32(0)) {
		return errors.New("lanshare: frame too large")
	}
	var hdr [5]byte
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// readFrame reads one frame, rejecting any payload longer than maxLen BEFORE
// allocating, so a malicious length prefix cannot exhaust memory.
func readFrame(r io.Reader, maxLen uint32) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	typ := hdr[0]
	length := binary.BigEndian.Uint32(hdr[1:])
	if length > maxLen {
		return 0, nil, fmt.Errorf("lanshare: frame length %d exceeds cap %d", length, maxLen)
	}
	if length == 0 {
		return typ, nil, nil
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return typ, buf, nil
}

// writeJSON marshals v and writes it as a control frame of the given type.
func writeJSON(w io.Writer, typ byte, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(payload) > maxControlFrame {
		return errors.New("lanshare: control frame too large")
	}
	return writeFrame(w, typ, payload)
}

// readControl reads a control frame, enforcing the expected type and the control
// size cap, and unmarshals it into v.
func readControl(r io.Reader, wantType byte, v any) error {
	typ, payload, err := readFrame(r, maxControlFrame)
	if err != nil {
		return err
	}
	if typ == msgError {
		var we wireError
		_ = json.Unmarshal(payload, &we)
		if we.Message == "" {
			we.Message = "remote error"
		}
		return fmt.Errorf("lanshare: remote: %s", we.Message)
	}
	if typ != wantType {
		return fmt.Errorf("lanshare: unexpected frame type %d (want %d)", typ, wantType)
	}
	return json.Unmarshal(payload, v)
}

// sendError best-effort reports a fatal reason to the peer before closing.
func sendError(w io.Writer, msg string) {
	_ = writeJSON(w, msgError, wireError{Message: msg})
}
