package clicore

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func DefaultExpiry() string {
	if value := strings.TrimSpace(os.Getenv("SHARE2US_DEFAULT_EXPIRY")); value != "" {
		return value
	}
	return "7d"
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
