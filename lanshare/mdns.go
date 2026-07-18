package lanshare

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
)

const (
	mdnsService = "_s2u._tcp"
	mdnsDomain  = "local."
)

// Advertise announces a live receiver on the local network via mDNS so a sender
// can find it by name (`--dest <name>`). The TXT record carries the cert
// fingerprint and mode, but never the passphrase — password-mode receivers are
// still discovered, but the sender must supply the password out-of-band.
func Advertise(instance string, info ListenInfo) (io.Closer, error) {
	instance = strings.TrimSpace(instance)
	if instance == "" {
		instance = "share2us"
	}
	txt := []string{
		"v=1",
		"f=" + info.Fingerprint,
		"mode=" + info.Mode,
	}
	server, err := zeroconf.Register(instance, mdnsService, mdnsDomain, info.Port, txt, nil)
	if err != nil {
		return nil, fmt.Errorf("lanshare: mdns register: %w", err)
	}
	return closerFunc(func() error { server.Shutdown(); return nil }), nil
}

// Discover browses the local network for a receiver whose instance name matches
// name (case-insensitive) and returns its address + fingerprint. Password is
// never carried over mDNS, so PairingInfo.Password is always empty here.
func Discover(ctx context.Context, name string, timeout time.Duration) (PairingInfo, error) {
	name = strings.TrimSpace(name)
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return PairingInfo{}, fmt.Errorf("lanshare: mdns resolver: %w", err)
	}
	entries := make(chan *zeroconf.ServiceEntry)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	found := make(chan PairingInfo, 1)
	go func() {
		for e := range entries {
			if !strings.EqualFold(e.Instance, name) {
				continue
			}
			host := ""
			if len(e.AddrIPv4) > 0 {
				host = e.AddrIPv4[0].String()
			} else if len(e.AddrIPv6) > 0 {
				host = e.AddrIPv6[0].String()
			}
			if host == "" || e.Port == 0 {
				continue
			}
			select {
			case found <- PairingInfo{Host: host, Port: e.Port, Fingerprint: txtValue(e.Text, "f")}:
			default:
			}
			return
		}
	}()

	if err := resolver.Browse(cctx, mdnsService, mdnsDomain, entries); err != nil {
		return PairingInfo{}, fmt.Errorf("lanshare: mdns browse: %w", err)
	}
	select {
	case pi := <-found:
		return pi, nil
	case <-cctx.Done():
		return PairingInfo{}, fmt.Errorf("lanshare: no receiver named %q found on the local network", name)
	}
}

func txtValue(text []string, key string) string {
	prefix := key + "="
	for _, t := range text {
		if strings.HasPrefix(t, prefix) {
			return strings.TrimPrefix(t, prefix)
		}
	}
	return ""
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }
