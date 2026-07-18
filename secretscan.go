package clicore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/zricethezav/gitleaks/v8/detect"
)

const DefaultSecretScanMaxBytes int64 = 5 * 1024 * 1024

type SecretScanOptions struct {
	MaxBytes int64
}

type SecretScanResult struct {
	Findings     []SecretFinding
	Skipped      bool
	SkipReason   string
	ScannedBytes int64
	Truncated    bool
}

type SecretFinding struct {
	RuleID      string
	Description string
	Line        int
	Redacted    string
	// Entropy is the gitleaks Shannon entropy of the match (0 when the rule is
	// not entropy-based); exposed for future tuning.
	Entropy float32
	// HighConfidence is true for named, high-precision credential rules (private
	// keys, cloud/provider tokens) — the class that agent/MCP uploads HARD-block.
	HighConfidence bool
}

// lowConfidenceSecretRules are gitleaks rule IDs whose matches carry enough false
// positives that, on the agent/MCP upload path, a hit is treated as SOFT (the
// agent may override, and it is logged) rather than a hard block. Every OTHER
// gitleaks default rule is a named, high-precision credential and is HARD-blocked
// (AGENTS.md #7: "hard-block high-confidence secrets").
var lowConfidenceSecretRules = map[string]bool{
	"generic-api-key": true,
}

// IsHighConfidenceSecretRule reports whether a gitleaks rule ID denotes a
// high-confidence secret. This is the concrete definition of "high confidence"
// used to hard-block agent uploads.
func IsHighConfidenceSecretRule(ruleID string) bool {
	ruleID = strings.TrimSpace(ruleID)
	return ruleID != "" && !lowConfidenceSecretRules[ruleID]
}

func ScanFileForSecrets(path string, opts SecretScanOptions) (SecretScanResult, error) {
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultSecretScanMaxBytes
	}

	file, err := os.Open(path)
	if err != nil {
		return SecretScanResult{}, err
	}
	defer file.Close()

	var buf bytes.Buffer
	limited := io.LimitReader(file, maxBytes+1)
	n, err := io.Copy(&buf, limited)
	if err != nil {
		return SecretScanResult{}, err
	}
	content := buf.Bytes()
	result := SecretScanResult{
		ScannedBytes: min64(n, maxBytes),
		Truncated:    n > maxBytes,
	}
	if result.Truncated {
		content = content[:maxBytes]
	}
	return finishSecretScan(content, result)
}

// ScanBytesForSecrets runs the same gitleaks scan over an in-memory buffer (e.g.
// the text of a `share_text` upload, which has no file on disk). Same skip rules
// (binary/non-UTF8) and byte cap as ScanFileForSecrets.
func ScanBytesForSecrets(content []byte, opts SecretScanOptions) (SecretScanResult, error) {
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultSecretScanMaxBytes
	}
	result := SecretScanResult{
		ScannedBytes: min64(int64(len(content)), maxBytes),
		Truncated:    int64(len(content)) > maxBytes,
	}
	if result.Truncated {
		content = content[:maxBytes]
	}
	return finishSecretScan(content, result)
}

// finishSecretScan applies the binary/UTF-8 skip and runs the detector, shared by
// the file and bytes entrypoints.
func finishSecretScan(content []byte, result SecretScanResult) (SecretScanResult, error) {
	if len(content) == 0 {
		return result, nil
	}
	if bytes.IndexByte(content, 0) >= 0 || !utf8.Valid(content) {
		result.Skipped = true
		result.SkipReason = "binary content"
		return result, nil
	}
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return SecretScanResult{}, fmt.Errorf("load gitleaks default rules: %w", err)
	}
	findings := detector.DetectBytes(content)
	result.Findings = make([]SecretFinding, 0, len(findings))
	for _, finding := range findings {
		line := finding.StartLine
		if line == 0 {
			line = 1
		}
		result.Findings = append(result.Findings, SecretFinding{
			RuleID:         finding.RuleID,
			Description:    finding.Description,
			Line:           line,
			Redacted:       RedactSecretFinding(finding.Match, finding.Secret),
			Entropy:        finding.Entropy,
			HighConfidence: IsHighConfidenceSecretRule(finding.RuleID),
		})
	}
	result.Findings = append(result.Findings, supplementalFindings(content)...)
	return result, nil
}

// supplementalFindings covers a few high-precision credential formats the gitleaks
// default rules under-detect (notably bare AWS access-key IDs, which gitleaks
// entropy-gates away). These formats have negligible false-positive rates, so a
// match is always high-confidence.
var supplementalSecretRules = []struct {
	id string
	re *regexp.Regexp
}{
	{"aws-access-key-id", regexp.MustCompile(`\b(?:AKIA|ASIA|A3T[A-Z0-9])[A-Z0-9]{16}\b`)},
	// gitleaks only flags a private key with a substantial body; block on the
	// header alone too, so an agent can't slip a key past by truncating the body.
	{"private-key-header", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)},
}

func supplementalFindings(content []byte) []SecretFinding {
	text := string(content)
	var out []SecretFinding
	for _, rule := range supplementalSecretRules {
		loc := rule.re.FindStringIndex(text)
		if loc == nil {
			continue
		}
		out = append(out, SecretFinding{
			RuleID:         rule.id,
			Description:    "high-confidence credential (" + rule.id + ")",
			Line:           strings.Count(text[:loc[0]], "\n") + 1,
			Redacted:       redactValue(text[loc[0]:loc[1]]),
			HighConfidence: true,
		})
	}
	return out
}

// HasHighConfidenceSecret reports whether any finding is a high-confidence secret.
func (r SecretScanResult) HasHighConfidenceSecret() bool {
	for _, f := range r.Findings {
		if f.HighConfidence {
			return true
		}
	}
	return false
}

func RedactSecretFinding(match, secret string) string {
	match = strings.TrimSpace(match)
	secret = strings.TrimSpace(secret)
	if secret == "" {
		if match == "" {
			return "REDACTED"
		}
		return redactValue(match)
	}
	redactedSecret := redactValue(secret)
	if match == "" {
		return redactedSecret
	}
	redacted := strings.ReplaceAll(match, secret, redactedSecret)
	if redacted == match {
		return redactedSecret
	}
	if len(redacted) > 160 {
		redacted = redacted[:157] + "..."
	}
	return redacted
}

func redactValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "REDACTED"
	}
	if len(value) <= 8 {
		return "REDACTED"
	}
	return value[:4] + "...REDACTED..." + value[len(value)-4:]
}

func SecretFindingsError(count int) error {
	if count == 1 {
		return errors.New("1 potential secret found; share cancelled")
	}
	return fmt.Errorf("%d potential secrets found; share cancelled", count)
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
