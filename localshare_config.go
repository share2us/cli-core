package clicore

import (
	"net"
	"strings"
)

// DeviceAlias maps a friendly name to an offline-share address (ip[:port] or an
// s2u:// pairing string). Used by `s2u config set device alias` and `--dest`.
type DeviceAlias struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
}

// SetDeviceAlias adds or updates an alias (case-insensitive name match).
func (c *Config) SetDeviceAlias(name, addr string) {
	name = strings.TrimSpace(name)
	addr = strings.TrimSpace(addr)
	for i := range c.Devices {
		if strings.EqualFold(c.Devices[i].Name, name) {
			c.Devices[i].Addr = addr
			return
		}
	}
	c.Devices = append(c.Devices, DeviceAlias{Name: name, Addr: addr})
}

// DeleteDeviceAlias removes an alias, returning whether one was removed.
func (c *Config) DeleteDeviceAlias(name string) bool {
	name = strings.TrimSpace(name)
	for i := range c.Devices {
		if strings.EqualFold(c.Devices[i].Name, name) {
			c.Devices = append(c.Devices[:i], c.Devices[i+1:]...)
			return true
		}
	}
	return false
}

// ResolveDeviceAlias returns the saved address for an alias name.
func (c Config) ResolveDeviceAlias(name string) (string, bool) {
	name = strings.TrimSpace(name)
	for _, d := range c.Devices {
		if strings.EqualFold(d.Name, name) {
			return d.Addr, true
		}
	}
	return "", false
}

// SetTrustedPeer marks an alias name or IP as trusted (deduplicated).
func (c *Config) SetTrustedPeer(ref string) {
	ref = strings.TrimSpace(ref)
	for _, existing := range c.TrustedPeers {
		if strings.EqualFold(existing, ref) {
			return
		}
	}
	c.TrustedPeers = append(c.TrustedPeers, ref)
}

// DeleteTrustedPeer removes a trusted ref, returning whether one was removed.
func (c *Config) DeleteTrustedPeer(ref string) bool {
	ref = strings.TrimSpace(ref)
	for i, existing := range c.TrustedPeers {
		if strings.EqualFold(existing, ref) {
			c.TrustedPeers = append(c.TrustedPeers[:i], c.TrustedPeers[i+1:]...)
			return true
		}
	}
	return false
}

// TrustedIPs resolves every trusted ref to a bare IP: literal IPs pass through,
// alias names resolve to their saved address's host. Non-resolvable refs are
// skipped. These IPs auto-accept inbound offline transfers without a password.
func (c Config) TrustedIPs() []string {
	var out []string
	for _, ref := range c.TrustedPeers {
		if ip := hostToIP(ref); ip != "" {
			out = append(out, ip)
			continue
		}
		if addr, ok := c.ResolveDeviceAlias(ref); ok {
			if ip := hostToIP(addr); ip != "" {
				out = append(out, ip)
			}
		}
	}
	return out
}

// hostToIP extracts a bare IP from a value that may be an IP, host:port, or an
// s2u:// pairing string. Returns "" if no literal IP can be determined.
func hostToIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "s2u://") {
		// s2u://host:port/... — pull the host.
		rest := strings.TrimPrefix(value, "s2u://")
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			rest = rest[:slash]
		}
		if q := strings.IndexByte(rest, '?'); q >= 0 {
			rest = rest[:q]
		}
		if host, _, err := net.SplitHostPort(rest); err == nil {
			value = host
		} else {
			value = rest
		}
	} else if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	if net.ParseIP(value) != nil {
		return value
	}
	return ""
}
