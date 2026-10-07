// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

// network-sandbox is a loopback-only HTTP proxy that forwards traffic to
// allowed destinations only. See ../doc/spec.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "embed"
)

//go:embed example.json
var exampleConfig []byte

// version is set at build time: go build -ldflags "-X main.version=..."
var version = "dev"

const copyright = `Copyright (C) 2026 Florian Mücke
This is free software - you are welcome to redistribute it under the terms
of the GNU General Public License version 3+; see LICENSE for details.
`

// defaultConfigName is the config file used, next to the exe, without -config.
const defaultConfigName = "network-sandbox.json"

const usage = `
Loopback-only HTTP proxy that forwards requests to allowed hosts only.

Usage: network-sandbox.exe [command] [-config <path>]

Commands:
  (none)    run in the console until Ctrl+C
  start     run in the background
  stop      stop the background proxy
  restart   stop, then start (applies config changes)
  status    list all running proxies; with -config, check the background
            proxy of that config only

Options:
  -config <path>   config file (default: network-sandbox.json next to the exe).
                   If it doesn't exist, an example is created there.
                   Each config has its own proxy: start, stop and restart
                   act on the proxy of this config.
  -help, -?, /?    show this help

Exit codes: 0 success, 1 error, 2 invalid arguments, 3 not running (status)

Agents use the proxy through HTTPS_PROXY=http://127.0.0.1:<port> and HTTP_PROXY.
`

var helpArgs = map[string]bool{"-?": true, "/?": true, "-h": true, "/h": true, "-help": true, "--help": true, "/help": true}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	for _, arg := range args {
		if helpArgs[strings.ToLower(arg)] {
			fmt.Fprintf(stderr, "network-sandbox %s - %s%s", version, copyright, usage)
			return 0
		}
	}
	command := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command, args = args[0], args[1:]
	}
	flags := flag.NewFlagSet("network-sandbox", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { fmt.Fprintln(stderr, "run network-sandbox.exe -help for usage") }
	configPath := flags.String("config", "", "path to the config file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() == 1 && command == "" {
		command = flags.Arg(0)
	} else if flags.NArg() > 0 {
		fmt.Fprintln(stderr, "network-sandbox: unexpected arguments:", flags.Args())
		flags.Usage()
		return 2
	}
	if command == "status" && *configPath == "" {
		return statusAll(stderr)
	}
	if *configPath == "" {
		*configPath = filepath.Join(exeDir(), defaultConfigName)
	}
	path, err := filepath.Abs(*configPath)
	if err != nil {
		return fail(stderr, err)
	}

	switch command {
	case "":
		return serve(path, stderr)
	case "start":
		return start(path, stderr)
	case "stop":
		return stop(path, stderr)
	case "restart":
		return restart(path, stderr)
	case "status":
		return status(path, stderr)
	default:
		fmt.Fprintf(stderr, "network-sandbox: unknown command %q\n", command)
		flags.Usage()
		return 2
	}
}

// serve runs the proxy in the foreground until interrupted.
func serve(configPath string, stderr io.Writer) int {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return fail(stderr, err)
	}
	logFile, err := openLog(cfg)
	if err != nil {
		return fail(stderr, err)
	}
	defer logFile.Close()
	log := slog.New(slog.NewTextHandler(io.MultiWriter(logFile, os.Stdout), &slog.HandlerOptions{Level: cfg.LogLevel}))

	ln, err := net.Listen("tcp", listenAddr(cfg))
	if err != nil {
		return fail(stderr, err)
	}
	proxy := NewProxy(cfg.Allowlist, cfg.AllowPrivate, log)
	srv := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       keepAliveTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	log.Info("started", "version", version, "listen", ln.Addr().String(), "allowlist_entries", cfg.Allowlist.Len(), "config", configPath)
	fmt.Fprintf(stderr, "network-sandbox: listening on %s, %d allowlist entries, logging to %s, config is %s\n",
		ln.Addr(), cfg.Allowlist.Len(), logFile.Name(), configPath)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(newLimitListener(ln, maxConnections, idleTimeout)) }()
	select {
	case err := <-serveErr:
		log.Error("server failed", "error", err)
		return fail(stderr, err)
	case <-ctx.Done():
	}

	proxy.CloseTunnels()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		srv.Close()
	}
	log.Info("stopped")
	return 0
}

// loadConfig loads the config. If it doesn't exist, it writes the example
// and fails: the proxy must not start with an allowlist nobody has reviewed.
func loadConfig(path string) (*Config, error) {
	cfg, err := LoadConfig(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := writeNewFile(path, exampleConfig); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("no config found; created example config %s - review it and start again", path)
	}
	return cfg, err
}

func openLog(cfg *Config) (*rotatingFile, error) {
	path := cfg.LogFile
	if !filepath.IsAbs(path) {
		path = filepath.Join(exeDir(), path)
	}
	return openRotatingFile(path, maxLogSize, logBackups)
}

func listenAddr(cfg *Config) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(cfg.Port)))
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "network-sandbox:", err)
	return 1
}

// writeNewFile creates path with data; it never overwrites an existing file.
func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
