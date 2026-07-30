package lanshare

import (
	"net"
	"testing"

	"github.com/grandcat/zeroconf"
)

func entryV4(ips ...string) *zeroconf.ServiceEntry {
	e := &zeroconf.ServiceEntry{}
	for _, s := range ips {
		e.AddrIPv4 = append(e.AddrIPv4, net.ParseIP(s))
	}
	return e
}

func TestBestAddrPrefersLAN(t *testing.T) {
	cases := []struct {
		name string
		e    *zeroconf.ServiceEntry
		want string
	}{
		{"lan over tailscale (tailscale first)", entryV4("100.64.0.5", "192.168.1.10"), "192.168.1.10"},
		{"lan over tailscale (lan first)", entryV4("192.168.1.10", "100.64.0.5"), "192.168.1.10"},
		{"tailscale only", entryV4("100.100.25.200"), "100.100.25.200"},
		{"lan over apipa", entryV4("169.254.9.9", "10.0.0.7"), "10.0.0.7"},
		{"lan over global", entryV4("8.8.8.8", "172.16.5.5"), "172.16.5.5"},
		{"apipa only still returned", entryV4("169.254.9.9"), "169.254.9.9"},
		{"tailscale over global", entryV4("8.8.8.8", "100.70.1.1"), "100.70.1.1"},
	}
	for _, c := range cases {
		if got := bestAddr(c.e); got != c.want {
			t.Errorf("%s: bestAddr = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestBestAddrFallsBackToIPv6(t *testing.T) {
	e := &zeroconf.ServiceEntry{AddrIPv6: []net.IP{net.ParseIP("fe80::1")}}
	if got := bestAddr(e); got != "fe80::1" {
		t.Fatalf("bestAddr = %q, want fe80::1", got)
	}
	if got := bestAddr(&zeroconf.ServiceEntry{}); got != "" {
		t.Fatalf("bestAddr(empty) = %q, want \"\"", got)
	}
}
