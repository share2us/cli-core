// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import (
	"net/netip"
	"testing"
)

func addrs(t *testing.T, ss ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func TestWantTailnet(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name string
		opts ScanOptions
		want bool
	}{
		{"whole-network scan enumerates the tailnet", ScanOptions{}, true},
		{"explicit targets do not grow on their own", ScanOptions{Targets: addrs(t, "10.0.0.1")}, false},
		// The regression this exists for: the desktop app's routine pass names its
		// known devices AND wants tailnet peers. Before, Targets suppressed them
		// unconditionally, so a Tailscale device never appeared between deep passes.
		{"explicit true adds the tailnet to a targeted scan", ScanOptions{Targets: addrs(t, "10.0.0.1"), IncludeTailscale: &yes}, true},
		{"explicit false suppresses it on a full scan", ScanOptions{IncludeTailscale: &no}, false},
	}
	for _, c := range cases {
		if got := wantTailnet(c.opts); got != c.want {
			t.Errorf("%s: wantTailnet = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestScanTargets(t *testing.T) {
	t.Run("explicit targets win over local subnets", func(t *testing.T) {
		got, _ := scanTargets(addrs(t, "10.0.0.1"), addrs(t, "192.168.1.5"), nil)
		if len(got) != 1 || got[0].String() != "10.0.0.1" {
			t.Fatalf("got %v, want only 10.0.0.1", got)
		}
	})
	t.Run("local subnets used when no explicit targets", func(t *testing.T) {
		got, _ := scanTargets(nil, addrs(t, "192.168.1.5"), nil)
		if len(got) != 1 || got[0].String() != "192.168.1.5" {
			t.Fatalf("got %v, want only 192.168.1.5", got)
		}
	})
	t.Run("peers are appended and marked as tailnet", func(t *testing.T) {
		got, tail := scanTargets(addrs(t, "10.0.0.1"), nil, addrs(t, "100.64.0.9"))
		if len(got) != 2 {
			t.Fatalf("got %v, want both target and peer", got)
		}
		peer := addrs(t, "100.64.0.9")[0]
		if !tail[peer] {
			t.Errorf("peer not marked as tailnet: %v", tail)
		}
		if tail[addrs(t, "10.0.0.1")[0]] {
			t.Errorf("explicit target wrongly marked as tailnet")
		}
	})
	t.Run("a peer already targeted is not probed twice", func(t *testing.T) {
		dup := "100.64.0.9"
		got, tail := scanTargets(addrs(t, dup), nil, addrs(t, dup))
		if len(got) != 1 {
			t.Fatalf("got %v, want one entry", got)
		}
		// It was already going to be probed as an explicit target, so it is not
		// ours to relabel.
		if tail[addrs(t, dup)[0]] {
			t.Errorf("duplicate wrongly marked as tailnet")
		}
	})
	t.Run("duplicate peers collapse", func(t *testing.T) {
		got, _ := scanTargets(nil, nil, addrs(t, "100.64.0.9", "100.64.0.9"))
		if len(got) != 1 {
			t.Fatalf("got %v, want one entry", got)
		}
	})
	t.Run("the caller's slice is never appended to", func(t *testing.T) {
		// A slice with spare capacity is the only shape that can be corrupted, so
		// build one deliberately rather than relying on what append happens to do.
		explicit := make([]netip.Addr, 1, 4)
		explicit[0] = addrs(t, "10.0.0.1")[0]
		scanTargets(explicit, nil, addrs(t, "100.64.0.9"))
		grown := explicit[:2]
		if grown[1].IsValid() {
			t.Fatalf("scanTargets wrote into the caller's backing array: %v", grown[1])
		}
	})
}
