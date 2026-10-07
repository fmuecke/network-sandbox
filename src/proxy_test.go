// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a log sink that is safe for concurrent writes and reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitForLog waits until a log line contains all given substrings.
func (b *syncBuffer) waitForLog(t *testing.T, parts ...string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
	lines:
		for line := range strings.SplitSeq(b.String(), "\n") {
			for _, p := range parts {
				if !strings.Contains(line, p) {
					continue lines
				}
			}
			return line
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no log line contains %q; log:\n%s", parts, b.String())
	return ""
}

func startProxy(t *testing.T, entries ...string) (*httptest.Server, *syncBuffer) {
	t.Helper()
	return startProxyWith(t, func(*Proxy) {}, entries...)
}

// startProxyWith starts a proxy that configure has adjusted, behind the same
// listener as in production.
func startProxyWith(t *testing.T, configure func(*Proxy), entries ...string) (*httptest.Server, *syncBuffer) {
	t.Helper()
	wl := newWhitelist()
	for _, e := range entries {
		if err := wl.add(e); err != nil {
			t.Fatal(err)
		}
	}
	logs := &syncBuffer{}
	p := NewProxy(wl, false, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	configure(p)
	srv := httptest.NewUnstartedServer(p)
	srv.Listener = newLimitListener(srv.Listener, maxConnections, p.idleTimeout)
	srv.Start()
	t.Cleanup(func() {
		p.CloseTunnels()
		srv.Close()
	})
	return srv, logs
}

func proxyClient(t *testing.T, proxy *httptest.Server, base *http.Transport) *http.Client {
	t.Helper()
	proxyURL, _ := url.Parse(proxy.URL)
	tr := &http.Transport{}
	if base != nil {
		tr = base.Clone()
	}
	tr.Proxy = http.ProxyURL(proxyURL)
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

func hostOf(rawURL string) string {
	u, _ := url.Parse(rawURL)
	return u.Host
}

func TestForwardHTTPAllowed(t *testing.T) {
	var gotHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		io.WriteString(w, "hello")
	}))
	defer upstream.Close()
	proxy, logs := startProxy(t, hostOf(upstream.URL))

	req, _ := http.NewRequest("GET", upstream.URL+"/path?access_token=query-secret", nil)
	req.Header.Set("Proxy-Foo", "secret")
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("X-Amz-Security-Token", "custom-secret")
	resp, err := proxyClient(t, proxy, nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "hello" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	if gotHeaders.Get("Proxy-Foo") != "" {
		t.Error("Proxy-* header was forwarded")
	}
	if gotHeaders.Get("Authorization") != "Bearer token" {
		t.Error("Authorization header was not forwarded")
	}
	logs.waitForLog(t, "method=GET", "target="+hostOf(upstream.URL), "decision=allow", "status=200", "bytes_down=5", "duration=")
	debug := logs.waitForLog(t, "level=DEBUG", "request headers", "/path?[redacted]", "User-Agent:[Go-http-client", "X-Amz-Security-Token:[[redacted]]")
	for _, secret := range []string{"Bearer token", "custom-secret", "query-secret"} {
		if strings.Contains(debug, secret) {
			t.Errorf("debug log contains %q: %s", secret, debug)
		}
	}
}

func TestRedactURL(t *testing.T) {
	for in, want := range map[string]string{
		"http://example.com/a/b":                        "http://example.com/a/b",
		"http://user:password@example.com:8080/a?sig=x": "http://example.com:8080/a?[redacted]",
	} {
		u, err := url.Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := redactURL(u); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// An allowed hostname must not lead to loopback or the local network, unless
// the config allows it. "localhost" stands for a name that resolves there.
func TestHostnameResolvingToNonPublicAddress(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello")
	}))
	defer upstream.Close()
	target := "localhost:" + strings.TrimPrefix(hostOf(upstream.URL), "127.0.0.1:")

	proxy, logs := startProxy(t, target)
	resp, body := rawConnect(t, proxy, target)
	if resp.StatusCode != 403 || !strings.Contains(body, "network-sandbox: "+target+" resolves to a non-public address") {
		t.Errorf("CONNECT: got %d %q", resp.StatusCode, body)
	}
	logs.waitForLog(t, "method=CONNECT", "target="+target, "decision=deny", "status=403", "error=")
	r, err := proxyClient(t, proxy, nil).Get("http://" + target + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 403 || !strings.Contains(string(b), "resolves to a non-public address") {
		t.Errorf("HTTP: got %d %q", r.StatusCode, b)
	}
	logs.waitForLog(t, "method=GET", "target="+target, "decision=deny", "status=403", "error=")

	proxy, _ = startProxyWith(t, func(p *Proxy) { p.allowPrivate = true }, target)
	r, err = proxyClient(t, proxy, nil).Get("http://" + target + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || string(b) != "hello" {
		t.Errorf("privateaddresses: allow: got %d %q", r.StatusCode, b)
	}
}

func TestIsPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"140.82.112.3":         true,
		"2606:4700::6810:1":    true,
		"64:ff9b::8c52:7003":   true, // NAT64 for 140.82.112.3
		"127.0.0.1":            false,
		"::1":                  false,
		"::ffff:127.0.0.1":     false,
		"10.1.2.3":             false,
		"172.16.0.1":           false,
		"192.168.1.1":          false,
		"169.254.169.254":      false, // cloud metadata
		"100.64.0.1":           false,
		"0.0.0.0":              false,
		"0.1.2.3":              false,
		"224.0.0.1":            false,
		"255.255.255.255":      false,
		"::":                   false,
		"fe80::1":              false,
		"fe80::1%eth0":         false,
		"fd00::1":              false,
		"ff02::1":              false,
		"64:ff9b::7f00:1":      false, // NAT64 for 127.0.0.1
		"64:ff9b::c0a8:101":    false, // NAT64 for 192.168.1.1
		"::ffff:140.82.112.3":  true,
		"2001:4860:4860::8888": true,
	} {
		if got := isPublic(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isPublic(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestConnectAllowed(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "secure hello")
	}))
	defer upstream.Close()
	proxy, logs := startProxy(t, hostOf(upstream.URL))

	client := proxyClient(t, proxy, upstream.Client().Transport.(*http.Transport))
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "secure hello" {
		t.Fatalf("got %q", body)
	}
	client.CloseIdleConnections() // ends the tunnel, which writes its log line
	line := logs.waitForLog(t, "method=CONNECT", "target="+hostOf(upstream.URL), "decision=allow", "status=200")
	if strings.Contains(line, "bytes_up=0 ") || strings.Contains(line, "bytes_down=0 ") {
		t.Errorf("tunnel byte counts missing: %s", line)
	}
}

func rawConnect(t *testing.T, proxy *httptest.Server, target string) (*http.Response, string) {
	t.Helper()
	conn, err := net.Dial("tcp", hostOf(proxy.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestDenied(t *testing.T) {
	proxy, logs := startProxy(t, "github.com:443")

	resp, body := rawConnect(t, proxy, "example.com:443")
	if resp.StatusCode != 403 || !strings.Contains(body, "network-sandbox: example.com:443 not in whitelist") {
		t.Errorf("CONNECT: got %d %q", resp.StatusCode, body)
	}
	logs.waitForLog(t, "method=CONNECT", "target=example.com:443", "decision=deny", "status=403")

	resp, body = rawConnect(t, proxy, hostOf(proxy.URL)) // the proxy itself
	if resp.StatusCode != 403 {
		t.Errorf("CONNECT to proxy: got %d %q", resp.StatusCode, body)
	}

	r, err := proxyClient(t, proxy, nil).Get("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 403 || !strings.Contains(string(b), "example.com:80 not in whitelist") {
		t.Errorf("HTTP: got %d %q", r.StatusCode, b)
	}
	logs.waitForLog(t, "method=GET", "target=example.com:80", "decision=deny", "status=403")
}

func TestOriginFormRejected(t *testing.T) {
	proxy, logs := startProxy(t, "github.com:443")
	resp, err := http.Get(proxy.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("got %d, want 400", resp.StatusCode)
	}
	logs.waitForLog(t, "decision=deny", "status=400")
}

func TestUpstreamUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	ln.Close()
	proxy, logs := startProxy(t, closed)

	resp, _ := rawConnect(t, proxy, closed)
	if resp.StatusCode != 502 {
		t.Errorf("CONNECT: got %d, want 502", resp.StatusCode)
	}
	logs.waitForLog(t, "method=CONNECT", "decision=allow", "status=502", "error=")

	r, err := proxyClient(t, proxy, nil).Get("http://" + closed + "/")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 502 {
		t.Errorf("HTTP: got %d, want 502", r.StatusCode)
	}
	logs.waitForLog(t, "method=GET", "decision=allow", "status=502", "error=")
}

func TestRunInvalidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.json")
	content := []byte(`{"port":8080,"whitelist":[]}`)
	os.WriteFile(path, content, 0o600)
	var stderr bytes.Buffer
	if code := run([]string{"-config", path}, &stderr); code == 0 {
		t.Error("exit code 0")
	}
	if !strings.Contains(stderr.String(), "whitelist is empty") {
		t.Errorf("no error message: %q", stderr.String())
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, content) {
		t.Error("existing config was modified")
	}
}

func TestRunMissingConfigCreatesExample(t *testing.T) {
	path := filepath.Join(t.TempDir(), "network-sandbox.json")
	var stderr bytes.Buffer
	if code := run([]string{"-config", path}, &stderr); code == 0 {
		t.Error("exit code 0: the proxy must not start with an unreviewed example")
	}
	if !strings.Contains(stderr.String(), "created example config") {
		t.Errorf("no message: %q", stderr.String())
	}
	if _, err := LoadConfig(path); err != nil {
		t.Errorf("created example is invalid: %v", err)
	}
}

func TestRunMissingConfigDirFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "network-sandbox.json")
	var stderr bytes.Buffer
	if code := run([]string{"-config", path}, &stderr); code == 0 {
		t.Error("exit code 0")
	}
	if strings.Contains(stderr.String(), "created example config") {
		t.Errorf("claimed to create a file it could not write: %q", stderr.String())
	}
}
