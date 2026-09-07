// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import (
	"context"
	"net"
	"testing"
	"time"
)

func cidr(t *testing.T, s string) net.Addr {
	t.Helper()
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	n.IP = ip
	return n
}

func TestLocalScanTargetsWalksSmallSubnetsOnly(t *testing.T) {
	got := localScanTargets([]net.Addr{
		cidr(t, "192.168.1.10/24"), // 254 hosts: walk it
		cidr(t, "10.0.0.5/16"),     // 65k hosts: far too wide, skip
		cidr(t, "127.0.0.1/8"),     // loopback: skip
		cidr(t, "169.254.3.4/16"),  // link-local: skip
	})
	var has192, hasSelf, has10 bool
	for _, a := range got {
		switch {
		case a.String() == "192.168.1.42":
			has192 = true
		case a.String() == "192.168.1.10":
			hasSelf = true // our own address is not worth probing
		case a.String() == "10.0.0.6":
			has10 = true
		}
	}
	if !has192 {
		t.Error("a /24 neighbour should be a target")
	}
	if hasSelf {
		t.Error("our own address should not be probed")
	}
	if has10 {
		t.Error("a /16 must be skipped: 65k probes is slow and looks like an attack")
	}
	if len(got) != 253 { // 254 usable minus ourselves
		t.Errorf("expected 253 targets from one /24, got %d", len(got))
	}
}

func TestLocalScanTargetsSkipsLoopbackAndIPv6(t *testing.T) {
	if got := localScanTargets([]net.Addr{cidr(t, "127.0.0.1/8")}); len(got) != 0 {
		t.Errorf("loopback produced %d targets", len(got))
	}
	if got := localScanTargets([]net.Addr{cidr(t, "fe80::1/64")}); len(got) != 0 {
		t.Errorf("IPv6 produced %d targets", len(got))
	}
}

// A real receiver must be recognised, and anything else must not be.
func TestProbeReceiverIdentifiesOnlyShare2Us(t *testing.T) {
	dir := t.TempDir()
	info, _, cancel := startReceiver(t, ReceiveOptions{
		Bind: "127.0.0.1", NoPassword: true, DestDir: dir,
	})
	defer cancel()

	addr := net.JoinHostPort("127.0.0.1", itoa(info.Port))
	fp, ok := probeReceiver(context.Background(), addr, 3*time.Second)
	if !ok {
		t.Fatal("a running receiver was not recognised by the probe")
	}
	// The whole point: what the probe returns is the pin a sender would use.
	if fp != info.Fingerprint {
		t.Fatalf("probe fingerprint %q != receiver's own %q", fp, info.Fingerprint)
	}

	// A plain TLS server that is not us must not be reported as a peer.
	other, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	go func() {
		c, aerr := other.Accept()
		if aerr == nil {
			c.Close()
		}
	}()
	if _, ok := probeReceiver(context.Background(), other.Addr().String(), 500*time.Millisecond); ok {
		t.Error("a non-Share2Us listener was reported as a peer")
	}
}

func itoa(i int) string { return net.JoinHostPort("", "")[1:] + itoaHelper(i) }

func itoaHelper(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
