//go:build windows

package daemonctl

import (
	"strings"
	"testing"
)

func TestSanitizePipeSegment(t *testing.T) {
	cases := map[string]string{
		"alice":      "alice",
		`CORP\bob`:   `CORP\bob`, // sanitize runs after the domain split in controlEndpoint
		"a b.c":      "a_b_c",
		"":           "default",
		"weird/../x": "weird_____x",
	}
	for in, want := range cases {
		if got := sanitizePipeSegment(in); got != want {
			t.Errorf("sanitizePipeSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestControlEndpointIsPerUserPipe(t *testing.T) {
	ep, err := controlEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ep, `\\.\pipe\share2us-daemon-`) {
		t.Fatalf("endpoint %q is not a share2us daemon pipe", ep)
	}
}
