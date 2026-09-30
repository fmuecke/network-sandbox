// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

// network-sandbox is a loopback-only HTTP proxy that forwards traffic to
// whitelisted destinations only. See ../doc/spec.md.
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
	"syscall"
	"time"

	_ "embed"
)

//go:embed example.ini
var exampleConfig []byte

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	exeDir := "."
	if exe, err := os.Executable(); err == nil {
		exeDir = filepath.Dir(exe)
	}
	flags := flag.NewFlagSet("network-sandbox", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", filepath.Join(exeDir, "network-sandbox.ini"), "path to the config file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintln(stderr, "network-sandbox: unexpected arguments:", flags.Args())
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "network-sandbox:", err)
		return 1
	}

	cfg, err := LoadConfig(*configPath)
	if errors.Is(err, fs.ErrNotExist) {
		// Don't start with a whitelist nobody has reviewed: write the example and stop.
		if err := writeNewFile(*configPath, exampleConfig); err != nil {
			return fail(err)
		}
		return fail(fmt.Errorf("no config found; created example config %s - review it and start again", *configPath))
	}
	if err != nil {
		return fail(err)
	}
	logPath := cfg.LogFile
	if !filepath.IsAbs(logPath) {
		logPath = filepath.Join(exeDir, logPath)
	}
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fail(err)
	}
	defer logFile.Close()
	log := slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: cfg.LogLevel}))

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(cfg.Port))))
	if err != nil {
		return fail(err)
	}
	proxy := NewProxy(cfg.Whitelist, log)
	srv := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: readHeaderTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("started", "listen", ln.Addr().String(), "whitelist_entries", cfg.Whitelist.Len(), "config", *configPath)
	fmt.Fprintf(stderr, "network-sandbox: listening on %s, %d whitelist entries, logging to %s\n",
		ln.Addr(), cfg.Whitelist.Len(), logPath)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	select {
	case err := <-serveErr:
		log.Error("server failed", "error", err)
		return fail(err)
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
