package clicore

import (
	"strings"
	"testing"
)

func TestQRIsText(t *testing.T) {
	if !QRIsText([]byte("hello share2us")) {
		t.Error("plain UTF-8 should be text")
	}
	if QRIsText([]byte{'a', 0x00, 'b'}) {
		t.Error("content with a NUL byte should not be text")
	}
	if QRIsText([]byte{0xff, 0xfe, 0xfd}) {
		t.Error("invalid UTF-8 should not be text")
	}
}

func TestRenderQR(t *testing.T) {
	art, err := RenderQR("hello share2us")
	if err != nil {
		t.Fatalf("RenderQR: %v", err)
	}
	if !strings.Contains(art, "█") {
		t.Errorf("expected half-block modules in output, got %q", art[:min(40, len(art))])
	}
	// Beyond the absolute QR byte capacity (well above QRContentMaxBytes) → error.
	if _, err := RenderQR(strings.Repeat("A", 5000)); err == nil {
		t.Error("expected an error for content beyond QR capacity")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
