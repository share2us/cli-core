package clicore

import (
	"os"
	"strings"
)

// APITokenPrefix marks a Share2Us personal access token (PAT) on the wire.
// Mirrors the server-side prefix; used to recognise env-provided tokens.
const APITokenPrefix = "s2u_pat_"

// APITokenEnv is the environment variable a caller (CI, automation) can set to
// authenticate with a personal access token instead of an interactive login.
const APITokenEnv = "SHARE2US_API_TOKEN"

// EnvAPIToken returns the trimmed value of SHARE2US_API_TOKEN, or "" if unset.
// When non-empty it takes precedence over the on-disk device credential.
func EnvAPIToken() string {
	return strings.TrimSpace(os.Getenv(APITokenEnv))
}

// IsAPIToken reports whether token is a personal access token. PATs carry no
// device identity, so device end-to-end features are unavailable with one.
func IsAPIToken(token string) bool {
	return strings.HasPrefix(strings.TrimSpace(token), APITokenPrefix)
}
