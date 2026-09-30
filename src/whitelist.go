// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type hostPort struct {
	host string
	port uint16
}

// Whitelist holds the allowed destinations. Hostnames and IP literals are
// kept apart: a hostname request never matches an IP entry and vice versa.
type Whitelist struct {
	exact     map[hostPort]bool       // github.com:443
	wildcards map[hostPort]bool       // *.githubusercontent.com:443, stored without "*."
	ips       map[netip.AddrPort]bool // 140.82.112.3:443, [2001:db8::1]:443
}

func newWhitelist() *Whitelist {
	return &Whitelist{
		exact:     map[hostPort]bool{},
		wildcards: map[hostPort]bool{},
		ips:       map[netip.AddrPort]bool{},
	}
}

func (w *Whitelist) Len() int {
	return len(w.exact) + len(w.wildcards) + len(w.ips)
}

func (w *Whitelist) add(entry string) error {
	host, port, err := splitHostPort(entry)
	if err != nil {
		return fmt.Errorf("invalid whitelist entry %q: %w", entry, err)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return fmt.Errorf("invalid whitelist entry %q: IPv6 zones are not supported", entry)
		}
		w.ips[netip.AddrPortFrom(addr, port)] = true
		return nil
	}
	if rest, ok := strings.CutPrefix(host, "*."); ok {
		name, ok := normalizeHostname(rest)
		if !ok {
			return fmt.Errorf("invalid whitelist entry %q: invalid domain", entry)
		}
		w.wildcards[hostPort{name, port}] = true
		return nil
	}
	name, ok := normalizeHostname(host)
	if !ok {
		return fmt.Errorf("invalid whitelist entry %q: invalid hostname", entry)
	}
	w.exact[hostPort{name, port}] = true
	return nil
}

// Check reports whether host:port is whitelisted. If so, it returns the
// normalized address to dial, which is exactly what was matched.
func (w *Whitelist) Check(host string, port uint16) (target string, ok bool) {
	if addr, err := netip.ParseAddr(host); err == nil {
		ap := netip.AddrPortFrom(addr, port)
		return ap.String(), w.ips[ap]
	}
	name, ok := normalizeHostname(host)
	if !ok {
		return "", false
	}
	target = net.JoinHostPort(name, strconv.Itoa(int(port)))
	if w.exact[hostPort{name, port}] {
		return target, true
	}
	// Try each parent domain, so *.x.com matches a.x.com and a.b.x.com, but not x.com.
	for i := 0; i < len(name); i++ {
		if name[i] == '.' && w.wildcards[hostPort{name[i+1:], port}] {
			return target, true
		}
	}
	return "", false
}

// splitHostPort splits "host:port" or "[ipv6]:port"; the port is required.
func splitHostPort(s string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	port, err := parsePort(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func parsePort(s string) (uint16, error) {
	if s == "" || len(s) > 5 || strings.Trim(s, "0123456789") != "" {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	n, _ := strconv.Atoi(s)
	if n < 1 || n > 65535 {
		return 0, errors.New("port must be between 1 and 65535")
	}
	return uint16(n), nil
}

// normalizeHostname lowercases h, strips one trailing dot, and validates it
// as a DNS name.
func normalizeHostname(h string) (string, bool) {
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" || len(h) > 253 {
		return "", false
	}
	for label := range strings.SplitSeq(h, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return h, true
}
