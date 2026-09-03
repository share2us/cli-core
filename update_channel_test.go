package clicore

import "testing"

func TestResolveUpdateChannel(t *testing.T) {
	t.Setenv(UpdateChannelEnv, "")
	if got := ResolveUpdateChannel(Config{}); got != UpdateChannelStable {
		t.Fatalf("default = %q", got)
	}
	if got := ResolveUpdateChannel(Config{UpdateChannel: "beta"}); got != UpdateChannelBeta {
		t.Fatalf("config beta = %q", got)
	}
	if got := ResolveUpdateChannel(Config{UpdateChannel: "nightly"}); got != UpdateChannelStable {
		t.Fatalf("bad config value should fall back to stable, got %q", got)
	}
	t.Setenv(UpdateChannelEnv, "Beta")
	if got := ResolveUpdateChannel(Config{UpdateChannel: "stable"}); got != UpdateChannelBeta {
		t.Fatalf("env should win, got %q", got)
	}
	if _, err := NormalizeUpdateChannel("nightly"); err == nil {
		t.Fatal("expected an error for an unknown channel")
	}
}
