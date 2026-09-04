package lanshare

import (
	"strings"
	"testing"
)

func TestSafetyNumberShapeAndStability(t *testing.T) {
	const fp = "b676f58a180a7fc204ab3a1c0d24eb9eec33b66faa066569eef3fa0d8096d37c"
	got := SafetyNumber(fp)
	if len(got) != 24 || got != SafetyNumber(strings.ToUpper(fp)) {
		t.Fatalf("SafetyNumber = %q (len %d)", got, len(got))
	}
	for i, ch := range got {
		if (i+1)%5 == 0 {
			if ch != ' ' {
				t.Fatalf("expected space at %d in %q", i, got)
			}
		} else if ch < '0' || ch > '9' {
			t.Fatalf("expected digit at %d in %q", i, got)
		}
	}
	if SafetyNumber("") != "" {
		t.Fatal("empty fingerprint must give an empty number")
	}
	if SafetyNumber(fp) == SafetyNumber("0"+fp[1:]) {
		t.Fatal("different fingerprints must differ")
	}
	// Independent of the 6-digit code's bits.
	if strings.Contains(strings.ReplaceAll(got, " ", ""), strings.ReplaceAll(VerifyCode(fp), " ", "")) {
		t.Fatal("safety number should not embed the verify code")
	}
}
