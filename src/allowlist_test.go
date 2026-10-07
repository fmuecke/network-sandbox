// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import "testing"

func TestAllowlistCheck(t *testing.T) {
	allowlist := newAllowlist()
	for _, e := range []string{
		"github.com:443",
		"*.githubusercontent.com:443",
		"140.82.112.3:443",
		"[2001:db8::1]:443",
		"Example.ORG.:80",
	} {
		if err := allowlist.add(e); err != nil {
			t.Fatalf("add(%q): %v", e, err)
		}
	}
	tests := []struct {
		host   string
		port   uint16
		target string // "" means denied
	}{
		{"github.com", 443, "github.com:443"},
		{"GitHub.COM", 443, "github.com:443"},
		{"github.com.", 443, "github.com:443"},
		{"github.com", 80, ""},
		{"api.github.com", 443, ""},
		{"raw.githubusercontent.com", 443, "raw.githubusercontent.com:443"},
		{"a.b.githubusercontent.com", 443, "a.b.githubusercontent.com:443"},
		{"githubusercontent.com", 443, ""},
		{"evilgithubusercontent.com", 443, ""},
		{"githubusercontent.com.evil.com", 443, ""},
		{"140.82.112.3", 443, "140.82.112.3:443"},
		{"140.82.112.3", 80, ""},
		{"2001:0db8::1", 443, "[2001:db8::1]:443"},
		{"example.org", 80, "example.org:80"},
		{"localhost", 443, ""},
		{"127.0.0.1", 443, ""},
		{"", 443, ""},
		{"github.com\x00", 443, ""},
		{"*.githubusercontent.com", 443, ""},
	}
	for _, tt := range tests {
		target, ok := allowlist.Check(tt.host, tt.port)
		if ok != (tt.target != "") || (ok && target != tt.target) {
			t.Errorf("Check(%q, %d) = %q, %v; want %q", tt.host, tt.port, target, ok, tt.target)
		}
	}
}

func TestAllowlistIPAndHostnameAreSeparate(t *testing.T) {
	allowlist := newAllowlist()
	allowlist.add("1.2.3.4:443")
	allowlist.add("*.4:443") // a wildcard over a numeric label must not match an IP literal
	if _, ok := allowlist.Check("1.2.3.4", 443); !ok {
		t.Error("IP entry should match the IP literal")
	}
	allowlist = newAllowlist()
	allowlist.add("*.4:443")
	if _, ok := allowlist.Check("1.2.3.4", 443); ok {
		t.Error("hostname wildcard matched an IP literal")
	}
}

func TestAllowlistInvalidEntries(t *testing.T) {
	for _, e := range []string{
		"github.com",
		"github.com:0",
		"github.com:65536",
		"github.com:+443",
		"github.com:*",
		"github.com:80-90",
		"*github.com:443",
		"a.*.com:443",
		"*.*.com:443",
		"*:443",
		"::1:443",
		"gi thub.com:443",
		"github..com:443",
		"[fe80::1%eth0]:443",
	} {
		if err := newAllowlist().add(e); err == nil {
			t.Errorf("add(%q) accepted an invalid entry", e)
		}
	}
}
