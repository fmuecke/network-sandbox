// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"log/slog"
	"strings"
	"testing"
)

// TestParseConfigExample checks that the embedded example config is valid.
func TestParseConfigExample(t *testing.T) {
	exampleConfig := string(exampleConfig)
	for name, input := range map[string]string{
		"plain":    exampleConfig,
		"bom":      "\xef\xbb\xbf" + exampleConfig,
		"crlf":     strings.ReplaceAll(exampleConfig, "\n", "\r\n"),
		"mixed-cs": strings.Replace(exampleConfig, "[network-sandbox]", "[Network-Sandbox]", 1),
	} {
		cfg, err := ParseConfig(strings.NewReader(input))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if cfg.Port != 8080 || cfg.LogFile != "network-sandbox.log" || cfg.LogLevel != slog.LevelInfo || cfg.AllowPrivate {
			t.Errorf("%s: got %+v", name, cfg)
		}
		if cfg.Whitelist.Len() != 7 {
			t.Errorf("%s: %d whitelist entries, want 7", name, cfg.Whitelist.Len())
		}
	}
}

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader("[network-sandbox]\nport=3128\n[whitelist]\ngithub.com:443\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogFile != "network-sandbox.log" || cfg.LogLevel != slog.LevelInfo {
		t.Errorf("defaults not applied: %+v", cfg)
	}
}

func TestParseConfigPrivateAddresses(t *testing.T) {
	for value, want := range map[string]bool{"allow": true, "Allow": true, "deny": false} {
		cfg, err := ParseConfig(strings.NewReader("[network-sandbox]\nport=3128\nprivateaddresses=" + value + "\n[whitelist]\ngithub.com:443\n"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.AllowPrivate != want {
			t.Errorf("privateaddresses=%s: AllowPrivate = %v, want %v", value, cfg.AllowPrivate, want)
		}
	}
}

func TestParseConfigErrors(t *testing.T) {
	const wl = "[whitelist]\ngithub.com:443\n"
	for name, input := range map[string]string{
		"missing port":       "[network-sandbox]\n" + wl,
		"invalid port":       "[network-sandbox]\nport=abc\n" + wl,
		"port zero":          "[network-sandbox]\nport=0\n" + wl,
		"port too large":     "[network-sandbox]\nport=65536\n" + wl,
		"unknown key":        "[network-sandbox]\nport=8080\nlisten=0.0.0.0\n" + wl,
		"duplicate key":      "[network-sandbox]\nport=8080\nport=8081\n" + wl,
		"bad loglevel":       "[network-sandbox]\nport=8080\nloglevel=trace\n" + wl,
		"bad private":        "[network-sandbox]\nport=8080\nprivateaddresses=yes\n" + wl,
		"empty logfile":      "[network-sandbox]\nport=8080\nlogfile=\n" + wl,
		"no equals":          "[network-sandbox]\nport 8080\n" + wl,
		"unknown section":    "[network-sandbox]\nport=8080\n[blacklist]\nevil.com:443\n" + wl,
		"outside section":    "port=8080\n[network-sandbox]\nport=8080\n" + wl,
		"empty whitelist":    "[network-sandbox]\nport=8080\n[whitelist]\n# nothing\n",
		"bad whitelist line": "[network-sandbox]\nport=8080\n[whitelist]\ngithub.com\n",
	} {
		if _, err := ParseConfig(strings.NewReader(input)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestStripComment(t *testing.T) {
	for in, want := range map[string]string{
		"# comment":              "",
		"; comment":              "",
		"port=8080 # comment":    "port=8080 ",
		"port=8080\t; comment":   "port=8080\t",
		`logfile=C:\a;b\x#y.log`: `logfile=C:\a;b\x#y.log`,
		"github.com:443  # note": "github.com:443  ",
	} {
		if got := stripComment(in); got != want {
			t.Errorf("stripComment(%q) = %q, want %q", in, got, want)
		}
	}
}
