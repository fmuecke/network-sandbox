// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

type Config struct {
	Port      uint16
	LogFile   string
	LogLevel  slog.Level
	Whitelist *Whitelist
}

var logLevels = map[string]slog.Level{
	"error": slog.LevelError,
	"warn":  slog.LevelWarn,
	"info":  slog.LevelInfo,
	"debug": slog.LevelDebug,
}

func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, err := ParseConfig(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// ParseConfig reads the INI config. Anything unexpected is an error: the
// proxy must not start with a config it only partly understood.
func ParseConfig(r io.Reader) (*Config, error) {
	cfg := &Config{LogFile: "network-sandbox.log", LogLevel: slog.LevelInfo}
	wl := newWhitelist()
	seen := map[string]bool{}
	section := ""

	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		text := sc.Text()
		if n == 1 {
			text = strings.TrimPrefix(text, string(rune(0xFEFF))) // UTF-8 BOM written by Notepad
		}
		line := strings.TrimSpace(stripComment(text))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section != "network-sandbox" && section != "whitelist" {
				return nil, fmt.Errorf("line %d: unknown section [%s]", n, section)
			}
			continue
		}
		switch section {
		case "network-sandbox":
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return nil, fmt.Errorf("line %d: expected key=value", n)
			}
			key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
			if seen[key] {
				return nil, fmt.Errorf("line %d: duplicate key %q", n, key)
			}
			seen[key] = true
			switch key {
			case "port":
				port, err := parsePort(value)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", n, err)
				}
				cfg.Port = port
			case "logfile":
				if value == "" {
					return nil, fmt.Errorf("line %d: logfile is empty", n)
				}
				cfg.LogFile = value
			case "loglevel":
				level, ok := logLevels[strings.ToLower(value)]
				if !ok {
					return nil, fmt.Errorf("line %d: loglevel must be error, warn, info or debug", n)
				}
				cfg.LogLevel = level
			default:
				return nil, fmt.Errorf("line %d: unknown key %q", n, key)
			}
		case "whitelist":
			if err := wl.add(line); err != nil {
				return nil, fmt.Errorf("line %d: %w", n, err)
			}
		default:
			return nil, fmt.Errorf("line %d: entry outside of a section", n)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !seen["port"] {
		return nil, errors.New("missing required key port in [network-sandbox]")
	}
	if wl.Len() == 0 {
		return nil, errors.New("whitelist is empty")
	}
	cfg.Whitelist = wl
	return cfg, nil
}

// stripComment removes a # or ; comment that starts the line or follows whitespace.
func stripComment(s string) string {
	for i := 0; i < len(s); i++ {
		if (s[i] == '#' || s[i] == ';') && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			return s[:i]
		}
	}
	return s
}
