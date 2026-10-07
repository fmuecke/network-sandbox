// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestParseConfigExample(t *testing.T) {
	if !json.Valid(exampleConfig) {
		t.Fatal("embedded example is not standard JSON")
	}
	for name, input := range map[string]string{
		"plain": string(exampleConfig),
		"bom":   "\xef\xbb\xbf" + string(exampleConfig),
		"crlf":  strings.ReplaceAll(string(exampleConfig), "\n", "\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := ParseConfig(strings.NewReader(input))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Port != 8080 || cfg.LogFile != "network-sandbox.log" || cfg.LogLevel != slog.LevelInfo || cfg.AllowPrivate {
				t.Errorf("got %+v", cfg)
			}
			if cfg.Allowlist.Len() != 5 {
				t.Errorf("%d allowlist entries, want 5", cfg.Allowlist.Len())
			}
		})
	}
}

func TestParseConfigJSON(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader(`{"port":3128,"allowed":["github.com:443"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 3128 || cfg.LogFile != "network-sandbox.log" || cfg.LogLevel != slog.LevelInfo || cfg.AllowPrivate || cfg.Allowlist.Len() != 1 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if _, ok := cfg.Allowlist.Check("github.com", 443); !ok {
		t.Error("configured host not allowed")
	}
	if _, ok := cfg.Allowlist.Check("example.com", 443); ok {
		t.Error("unconfigured host allowed")
	}
}

func TestParseConfigValues(t *testing.T) {
	input := `{"port":65535,"logfile":"C:\\logs\\a;b#c.log","loglevel":"DEBUG","privateaddresses":"Allow","allowed":["github.com:443","*.githubusercontent.com:443","127.0.0.1:80","[::1]:443"]}`
	cfg, err := ParseConfig(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 65535 || cfg.LogFile != `C:\logs\a;b#c.log` || cfg.LogLevel != slog.LevelDebug || !cfg.AllowPrivate {
		t.Errorf("got %+v", cfg)
	}
	for host, port := range map[string]uint16{"github.com": 443, "raw.githubusercontent.com": 443, "127.0.0.1": 80, "::1": 443} {
		if _, ok := cfg.Allowlist.Check(host, port); !ok {
			t.Errorf("%s:%d not allowed", host, port)
		}
	}
}

func TestParseConfigLogLevels(t *testing.T) {
	for name, want := range logLevels {
		input := fmt.Sprintf(`{"port":8080,"loglevel":%q,"allowed":["github.com:443"]}`, name)
		cfg, err := ParseConfig(strings.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.LogLevel != want {
			t.Errorf("%s: got %v, want %v", name, cfg.LogLevel, want)
		}
	}
}

func TestParseConfigPrivateAddresses(t *testing.T) {
	for value, want := range map[string]bool{"allow": true, "Allow": true, "deny": false} {
		input := fmt.Sprintf(`{"port":3128,"privateaddresses":%q,"allowed":["github.com:443"]}`, value)
		cfg, err := ParseConfig(strings.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.AllowPrivate != want {
			t.Errorf("privateaddresses=%s: got %v, want %v", value, cfg.AllowPrivate, want)
		}
	}
}

func TestParseConfigErrors(t *testing.T) {
	for name, input := range map[string]string{
		"empty input": ``,
		"legacy format": `[network-sandbox]
port=8080
[allowed]
github.com:443`,
		"not an object":               `[]`,
		"null object":                 `null`,
		"missing port":                `{"allowed":["github.com:443"]}`,
		"invalid port":                `{"port":"abc","allowed":["github.com:443"]}`,
		"port zero":                   `{"port":0,"allowed":["github.com:443"]}`,
		"port negative":               `{"port":-1,"allowed":["github.com:443"]}`,
		"port too large":              `{"port":65536,"allowed":["github.com:443"]}`,
		"port fraction":               `{"port":8080.5,"allowed":["github.com:443"]}`,
		"port string":                 `{"port":"8080","allowed":["github.com:443"]}`,
		"bad loglevel":                `{"port":8080,"loglevel":"trace","allowed":["github.com:443"]}`,
		"bad private":                 `{"port":8080,"privateaddresses":"yes","allowed":["github.com:443"]}`,
		"empty logfile":               `{"port":8080,"logfile":"","allowed":["github.com:443"]}`,
		"blank logfile":               `{"port":8080,"logfile":" ","allowed":["github.com:443"]}`,
		"missing allowed":             `{"port":8080}`,
		"empty allowlist":             `{"port":8080,"allowed":[]}`,
		"bad allowlist entry":         `{"port":8080,"allowed":["github.com"]}`,
		"null allowlist entry":        `{"port":8080,"allowed":[null]}`,
		"unknown key":                 `{"port":8080,"listen":"0.0.0.0","allowed":["github.com:443"]}`,
		"wrong key case":              `{"Port":8080,"allowed":["github.com:443"]}`,
		"mixed key case":              `{"port":8080,"PORT":8081,"allowed":["github.com:443"]}`,
		"nested section":              `{"network-sandbox":{"port":8080},"allowed":["github.com:443"]}`,
		"comment":                     `{"port":8080,/* comment */"allowed":["github.com:443"]}`,
		"trailing comma":              `{"port":8080,"allowed":["github.com:443"],}`,
		"truncated":                   `{"port":8080,"allowed":["github.com:443"]`,
		"trailing object":             `{"port":8080,"allowed":["github.com:443"]} {}`,
		"trailing null":               `{"port":8080,"allowed":["github.com:443"]} null`,
		"trailing garbage":            `{"port":8080,"allowed":["github.com:443"]} garbage`,
		"null port":                   `{"port":null,"logfile":"network-sandbox.log","loglevel":"info","privateaddresses":"deny","allowed":["github.com:443"]}`,
		"wrong type port":             `{"port":true,"logfile":"network-sandbox.log","loglevel":"info","privateaddresses":"deny","allowed":["github.com:443"]}`,
		"duplicate port":              `{"port":8080,"logfile":"network-sandbox.log","loglevel":"info","privateaddresses":"deny","allowed":["github.com:443"],"port":8080}`,
		"null logfile":                `{"port":8080,"logfile":null,"loglevel":"info","privateaddresses":"deny","allowed":["github.com:443"]}`,
		"wrong type logfile":          `{"port":8080,"logfile":true,"loglevel":"info","privateaddresses":"deny","allowed":["github.com:443"]}`,
		"duplicate logfile":           `{"port":8080,"logfile":"network-sandbox.log","loglevel":"info","privateaddresses":"deny","allowed":["github.com:443"],"logfile":"network-sandbox.log"}`,
		"null loglevel":               `{"port":8080,"logfile":"network-sandbox.log","loglevel":null,"privateaddresses":"deny","allowed":["github.com:443"]}`,
		"wrong type loglevel":         `{"port":8080,"logfile":"network-sandbox.log","loglevel":true,"privateaddresses":"deny","allowed":["github.com:443"]}`,
		"duplicate loglevel":          `{"port":8080,"logfile":"network-sandbox.log","loglevel":"info","privateaddresses":"deny","allowed":["github.com:443"],"loglevel":"info"}`,
		"null privateaddresses":       `{"port":8080,"logfile":"network-sandbox.log","loglevel":"info","privateaddresses":null,"allowed":["github.com:443"]}`,
		"wrong type privateaddresses": `{"port":8080,"logfile":"network-sandbox.log","loglevel":"info","privateaddresses":true,"allowed":["github.com:443"]}`,
		"duplicate privateaddresses":  `{"port":8080,"logfile":"network-sandbox.log","loglevel":"info","privateaddresses":"deny","allowed":["github.com:443"],"privateaddresses":"deny"}`,
		"null allowed":                `{"port":8080,"logfile":"network-sandbox.log","loglevel":"info","privateaddresses":"deny","allowed":null}`,
		"wrong type allowed":          `{"port":8080,"logfile":"network-sandbox.log","loglevel":"info","privateaddresses":"deny","allowed":true}`,
		"duplicate allowed":           `{"port":8080,"logfile":"network-sandbox.log","loglevel":"info","privateaddresses":"deny","allowed":["github.com:443"],"allowed":["github.com:443"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig(strings.NewReader(input)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
