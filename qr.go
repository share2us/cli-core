package clicore

import (
	"unicode/utf8"

	qrcode "github.com/skip2/go-qrcode"
)

// QRContentMaxBytes caps an in-terminal *content* QR so it stays scannable by a
// phone camera. It is far below the raw QR byte-mode ceiling (2953 bytes / a
// 177x177-module code): a terminal renders each module ~one character cell, so a
// dense high-version code can't be resolved from a screen. Tunable.
const QRContentMaxBytes = 1000

// QRContentWarnBytes: above this (but under the hard cap) a content QR still
// encodes, but the code is dense enough that it may be harder to scan.
const QRContentWarnBytes = 300

// QRIsText reports whether b is safe to embed as QR text — valid UTF-8 with no
// NUL bytes (the same heuristic used to gate --live text streaming).
func QRIsText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, c := range b {
		if c == 0 {
			return false
		}
	}
	return true
}

// RenderQR returns a QR code of content drawn with Unicode half-blocks (two
// modules per character row) at error-correction level M, with a quiet-zone
// border. It errors only if content exceeds the absolute QR capacity; callers
// should enforce QRContentMaxBytes first for scannability.
func RenderQR(content string) (string, error) {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return "", err
	}
	return q.ToSmallString(false), nil
}
