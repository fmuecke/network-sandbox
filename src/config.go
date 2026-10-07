// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

type Config struct {
	Port         uint16
	LogFile      string
	LogLevel     slog.Level
	AllowPrivate bool // hostname entries may resolve to non-public addresses
	Whitelist    *Whitelist
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

// ParseConfig reads one JSON object. Anything unexpected is an error: the
// proxy must not start with a config it only partly understood.
func ParseConfig(r io.Reader) (*Config, error) {
	reader := bufio.NewReader(r)
	if bom, _ := reader.Peek(3); string(bom) == "\xef\xbb\xbf" {
		reader.Discard(3) // UTF-8 BOM written by Notepad
	}
	dec := json.NewDecoder(reader)
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('{') {
		return nil, errors.New("config must be a JSON object")
	}

	cfg := &Config{LogFile: "network-sandbox.log"}
	logLevel, privateAddresses := "info", "deny"
	var entries []string
	seen := map[string]bool{}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key := token.(string)
		if seen[key] {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		var target any
		switch key {
		case "port":
			target = &cfg.Port
		case "logfile":
			target = &cfg.LogFile
		case "loglevel":
			target = &logLevel
		case "privateaddresses":
			target = &privateAddresses
		case "whitelist":
			target = &entries
		default:
			return nil, fmt.Errorf("unknown key %q", key)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		if string(value) == "null" {
			return nil, fmt.Errorf("%s must not be null", key)
		}
		if err := json.Unmarshal(value, target); err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("unexpected data after config object")
	}
	if !seen["port"] {
		return nil, errors.New("missing required key port")
	}
	if cfg.Port == 0 {
		return nil, errors.New("port must be between 1 and 65535")
	}
	if strings.TrimSpace(cfg.LogFile) == "" {
		return nil, errors.New("logfile is empty")
	}
	level, ok := logLevels[strings.ToLower(logLevel)]
	if !ok {
		return nil, errors.New("loglevel must be error, warn, info or debug")
	}
	cfg.LogLevel = level
	switch strings.ToLower(privateAddresses) {
	case "allow":
		cfg.AllowPrivate = true
	case "deny":
	default:
		return nil, errors.New("privateaddresses must be deny or allow")
	}
	wl := newWhitelist()
	for i, entry := range entries {
		if err := wl.add(entry); err != nil {
			return nil, fmt.Errorf("whitelist[%d]: %w", i, err)
		}
	}
	if wl.Len() == 0 {
		return nil, errors.New("whitelist is empty")
	}
	cfg.Whitelist = wl
	return cfg, nil
}
