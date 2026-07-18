package clicore

import "testing"

func TestIsAPIToken(t *testing.T) {
	cases := map[string]bool{
		"s2u_pat_abc123":     true,
		"  s2u_pat_abc  ":    true,
		"s2s_device_session": false,
		"":                   false,
		"pat_s2u_nope":       false,
	}
	for token, want := range cases {
		if got := IsAPIToken(token); got != want {
			t.Errorf("IsAPIToken(%q) = %v, want %v", token, got, want)
		}
	}
}

func TestEnvAPIToken(t *testing.T) {
	t.Setenv(APITokenEnv, "  s2u_pat_xyz  ")
	if got := EnvAPIToken(); got != "s2u_pat_xyz" {
		t.Fatalf("EnvAPIToken() = %q, want trimmed s2u_pat_xyz", got)
	}
	t.Setenv(APITokenEnv, "")
	if got := EnvAPIToken(); got != "" {
		t.Fatalf("EnvAPIToken() unset = %q, want empty", got)
	}
}
