// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultExpiry is what to send as expires_in when the user did not ask for a
// duration. EMPTY MEANS "let the server decide", which is the correct answer:
// the expiry policy is the plan's, the server already holds it
// (default_expiry_hours), and expiry.Validate applies it when the request names
// nothing.
//
// It used to return "7d". That was a client guessing at a server policy, and on
// 2026-09-16 the guess became wrong: the Free plan's maximum dropped to 48h, so
// every default CLI upload was refused with expiry_denied -- the whole free tier
// broken by a constant in the client. Found by a two-node container test doing an
// ordinary `s2u <file> --device <name>`.
//
// SHARE2US_DEFAULT_EXPIRY still overrides, for anyone who wants a fixed value.
func DefaultExpiry() string {
	return strings.TrimSpace(os.Getenv("SHARE2US_DEFAULT_EXPIRY"))
}

func ParseDuration(value string) (time.Duration, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, fmt.Errorf("duration is required")
	}
	if hours, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return time.Duration(hours) * time.Hour, nil
	}
	if daysRaw, ok := strings.CutSuffix(trimmed, "d"); ok {
		days, err := strconv.ParseInt(daysRaw, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("duration must be a value like 24h, 7d, or integer hours")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	duration, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, fmt.Errorf("duration must be a value like 24h, 7d, or integer hours")
	}
	return duration, nil
}

func DurationForAPI(value string) (string, error) {
	duration, err := ParseDuration(value)
	if err != nil {
		return "", err
	}
	if duration <= 0 {
		return "", fmt.Errorf("duration must be positive")
	}
	return duration.String(), nil
}

// ExpiryForAPI translates a user-supplied expiry value into the wire fields for
// the upload/reshare API. "0", "none", "never", "keep", and "forever" mean the
// share is kept indefinitely (no expiry): noExpiry=true with an empty duration.
// Anything else is validated as a positive finite duration via DurationForAPI.
func ExpiryForAPI(value string) (expiresIn string, noExpiry bool, err error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0", "none", "never", "keep", "forever":
		return "", true, nil
	}
	expiresIn, err = DurationForAPI(value)
	return expiresIn, false, err
}
