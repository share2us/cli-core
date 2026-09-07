// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package lanshare

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/netip"
	"os/exec"

	"github.com/share2us/cli-core/internal/proc"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Discovery by probing instead of by announcement.
//
// mDNS cannot work on Windows: the responder inside svchost owns UDP 5353, so
// our own responder never sees a query, and DnsServiceRegister reports success
// while the OS publishes nothing (measured on Windows 10 19045 — todo VV). A
// machine there can find others and is itself invisible, which is worse than
// having no discovery at all because it looks like a network fault.
//
// A receiver is trivially identifiable without any announcement: it listens on
// DefaultPort and serves a self-signed certificate whose CommonName is a fixed
// marker, so a TLS handshake alone says "this is Share2Us" and hands back the
// certificate fingerprint.
//
// That fingerprint is worth more than the mDNS one. What a sender pins from an
// advert is whatever the TXT record claimed, which any device on the segment can
// forge; what a probe pins is the certificate of the host it just spoke to. So
// this path is not merely a fallback, it closes an impersonation window rather
// than moving it.
const scanCertCommonName = "share2us-lan"

// ScanOptions tunes a scan. The zero value is sensible.
type ScanOptions struct {
	// Port to probe (default DefaultPort).
	Port int
	// Timeout per host for dial + handshake (default 400ms). Scans run wide, not
	// deep, so a short timeout costs nothing but a slow host on a busy network.
	Timeout time.Duration
	// Concurrency caps in-flight probes (default 128). Also what keeps this from
	// looking like a flood to anything watching the network.
	Concurrency int
	// Targets overrides the address list. Empty means "work it out": every local
	// IPv4 subnet small enough to enumerate, plus tailnet peers.
	Targets []netip.Addr
	// IncludeTailscale asks the tailscale CLI for peers (default true). Peers are
	// enumerated, never scanned: the tailnet range is millions of addresses.
	IncludeTailscale *bool
	// SkipLocalSubnets probes only tailnet peers and leaves the local segment
	// alone. This is the polite default for a background discovery: enumerating a
	// handful of known peers is nothing like sweeping every address on a subnet.
	SkipLocalSubnets bool
}

// ScannedPeer is a host that answered a probe as a Share2Us receiver.
type ScannedPeer struct {
	Host        string
	Port        int
	Fingerprint string
	// ViaTailscale marks a peer found through the tailnet rather than a local
	// subnet, which is the case mDNS can never reach at all.
	ViaTailscale bool
}

// Addr renders host:port.
func (p ScannedPeer) Addr() string { return net.JoinHostPort(p.Host, strconv.Itoa(p.Port)) }

// Scan probes for receivers and returns the ones that answered. A host that is
// absent, firewalled or not running Share2Us simply does not appear; nothing is
// reported as an error, because on a real network most addresses are all three.
func Scan(ctx context.Context, opts ScanOptions) ([]ScannedPeer, error) {
	if opts.Port == 0 {
		opts.Port = DefaultPort
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 400 * time.Millisecond
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 128
	}
	targets := opts.Targets
	tailnet := map[netip.Addr]bool{}
	if len(targets) == 0 {
		if !opts.SkipLocalSubnets {
			ifaceAddrs, _ := net.InterfaceAddrs()
			targets = localScanTargets(ifaceAddrs)
		}
		if opts.IncludeTailscale == nil || *opts.IncludeTailscale {
			for _, a := range tailscalePeers(ctx) {
				if !tailnet[a] {
					tailnet[a] = true
					targets = append(targets, a)
				}
			}
		}
	}

	var (
		mu    sync.Mutex
		found []ScannedPeer
		wg    sync.WaitGroup
	)
	sem := make(chan struct{}, opts.Concurrency)
	for _, target := range targets {
		select {
		case <-ctx.Done():
			return found, ctx.Err()
		default:
		}
		wg.Add(1)
		go func(a netip.Addr) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			addr := net.JoinHostPort(a.String(), strconv.Itoa(opts.Port))
			fp, ok := probeReceiver(ctx, addr, opts.Timeout)
			if !ok {
				return
			}
			// Same rule as Browse: a device is never one of its own results.
			// A scan skips this machine's own addresses, but a second Share2Us
			// process here would still answer a probe.
			if isSelfFingerprint(fp) {
				return
			}
			mu.Lock()
			found = append(found, ScannedPeer{
				Host: a.String(), Port: opts.Port, Fingerprint: fp, ViaTailscale: tailnet[a],
			})
			mu.Unlock()
		}(target)
	}
	wg.Wait()
	sort.Slice(found, func(i, j int) bool { return found[i].Host < found[j].Host })
	return found, nil
}

// probeReceiver completes a TLS handshake and reports the peer's certificate
// fingerprint if it is a Share2Us receiver. The certificate is self-signed by
// design, so verification is skipped deliberately and the identity comes from
// the fingerprint the caller then pins — exactly what a pairing string carries.
func probeReceiver(ctx context.Context, addr string, timeout time.Duration) (string, bool) {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var fingerprint string
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // self-signed by design; identity is the fingerprint
		MinVersion:         tls.VersionTLS13,
	})
	if err := tlsConn.HandshakeContext(dctx); err != nil {
		return "", false
	}
	defer tlsConn.Close()
	for _, c := range tlsConn.ConnectionState().PeerCertificates {
		if c.Subject.CommonName == scanCertCommonName {
			if fingerprint == "" {
				fingerprint = certFingerprint(c.Raw)
			}
			return fingerprint, true
		}
	}
	return "", false
}

// localScanTargets turns the machine's own addresses into a list worth probing:
// every IPv4 subnet small enough to enumerate quickly, minus our own address.
//
// Anything wider than /22 is skipped outright. A /16 is 65k probes, which is
// both slow and the kind of traffic that makes security software take an
// interest — and a home or office segment is a /24 in practice.
func localScanTargets(ifaceAddrs []net.Addr) []netip.Addr {
	const minPrefix = 22 // /22 = 1024 addresses, the widest we will walk
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, a := range ifaceAddrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.To4() == nil {
			continue
		}
		self, ok := netip.AddrFromSlice(ipNet.IP.To4())
		if !ok || self.IsLoopback() || self.IsLinkLocalUnicast() {
			continue
		}
		ones, _ := ipNet.Mask.Size()
		if ones < minPrefix || ones > 30 {
			continue
		}
		prefix := netip.PrefixFrom(self, ones).Masked()
		// Starts after the network address and stops before the broadcast one:
		// neither is a host, and probing the broadcast address invites a reply
		// from every machine on the segment at once.
		for ip := prefix.Addr().Next(); prefix.Contains(ip) && prefix.Contains(ip.Next()); ip = ip.Next() {
			if ip == self || seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

// tailscalePeers lists tailnet peer addresses. They are ENUMERATED, never
// scanned: the tailnet is a /10 and walking it is not an option. This is also
// the only discovery that crosses subnets, which mDNS structurally cannot do.
func tailscalePeers(ctx context.Context) []netip.Addr {
	// Look first: on a machine without Tailscale this avoids starting a process
	// at all, which matters because a desktop app calls this on a timer.
	if _, err := exec.LookPath("tailscale"); err != nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "tailscale", "status", "--json")
	proc.Hide(cmd) // a GUI app has no console; without this Windows flashes one
	out, err := cmd.Output()
	if err != nil {
		return nil // not installed, or not up: nothing to add
	}
	var status struct {
		Peer map[string]struct {
			TailscaleIPs []string `json:"TailscaleIPs"`
			Online       bool     `json:"Online"`
		} `json:"Peer"`
	}
	if err := json.Unmarshal(out, &status); err != nil {
		return nil
	}
	var addrs []netip.Addr
	for _, p := range status.Peer {
		if !p.Online {
			continue
		}
		for _, s := range p.TailscaleIPs {
			if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
				addrs = append(addrs, a)
				break
			}
		}
	}
	return addrs
}
