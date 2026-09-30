// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests play a hostile client: one that opens connections and then
// leaves them idle or stalled.

const testIdleTimeout = 300 * time.Millisecond

func shortIdle(p *Proxy) { p.idleTimeout = testIdleTimeout }

// tcpServer runs handle for every connection to a local listener.
func tcpServer(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { conn.Close() })
			go handle(conn)
		}
	}()
	return ln.Addr().String()
}

// openTunnel sends a CONNECT and returns the connection with its reader.
func openTunnel(t *testing.T, proxy *httptest.Server, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", hostOf(proxy.URL))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second)) // fail instead of hanging
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT %s: status %d", target, resp.StatusCode)
	}
	return conn, r
}

func TestIdleTunnelIsClosed(t *testing.T) {
	silent := tcpServer(t, func(net.Conn) {})
	proxy, logs := startProxyWith(t, shortIdle, silent)

	_, r := openTunnel(t, proxy, silent)
	start := time.Now()
	if _, err := r.ReadByte(); err != io.EOF {
		t.Fatalf("idle tunnel: read returned %v, want EOF", err)
	}
	if idle := time.Since(start); idle < testIdleTimeout/2 {
		t.Errorf("tunnel was closed after %s, before the idle timeout", idle)
	}
	logs.waitForLog(t, "method=CONNECT", "target="+silent, "decision=allow", "status=200")
}

// Traffic in one direction keeps a tunnel open, like a download during which
// the client sends nothing.
func TestTunnelWithOneWayTrafficStaysOpen(t *testing.T) {
	const chunks = 12
	sender := tcpServer(t, func(conn net.Conn) {
		for range chunks {
			time.Sleep(testIdleTimeout / 4)
			conn.Write([]byte("x"))
		}
		conn.Close()
	})
	proxy, _ := startProxyWith(t, shortIdle, sender)

	_, r := openTunnel(t, proxy, sender)
	got, err := io.ReadAll(r)
	if err != nil || len(got) != chunks {
		t.Errorf("received %d of %d bytes, error %v", len(got), chunks, err)
	}
}

// A client that announces a request body and never sends it must not hold
// its connection.
func TestStalledRequestBodyIsCut(t *testing.T) {
	proxy, _ := startProxyWith(t, shortIdle, "github.com:443")
	conn, err := net.Dial("tcp", hostOf(proxy.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(conn, "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\n")
	if _, err := io.ReadAll(conn); err != nil {
		t.Errorf("stalled connection was not closed: %v", err)
	}
}

// An upstream that stops in the middle of a response must not hold the
// request, and the aborted transfer must still show up in the log.
func TestStalledResponseIsCutAndLogged(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "partial")
		w.(http.Flusher).Flush()
		<-release
	}))
	defer upstream.Close()
	defer close(release)
	proxy, logs := startProxyWith(t, shortIdle, hostOf(upstream.URL))

	resp, err := proxyClient(t, proxy, nil).Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "partial" || err == nil {
		t.Errorf("got %q, error %v; want the partial body and an error", body, err)
	}
	logs.waitForLog(t, "method=GET", "decision=allow", "status=200", "bytes_down=7")
}

func TestLimitListener(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := newLimitListener(inner, 2, time.Minute)
	accepted := make(chan net.Conn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	for range 3 {
		client, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
	}
	first := <-accepted
	<-accepted
	select {
	case <-accepted:
		t.Fatal("accepted a third connection beyond the limit of 2")
	case <-time.After(200 * time.Millisecond):
	}
	first.Close()
	first.Close() // closing twice must free one slot only
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("no connection accepted after one was closed")
	}
	select {
	case <-accepted:
		t.Fatal("closing a connection twice freed two slots")
	case <-time.After(200 * time.Millisecond):
	}
	ln.Close() // must also end an Accept that waits for a free slot
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
}

func TestLogRotation(t *testing.T) {
	const maxSize, backups = 200, 2
	path := filepath.Join(t.TempDir(), "sandbox.log")
	log, err := openRotatingFile(path, maxSize, backups)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 100 {
		if i == 50 { // a restart continues the file
			log.Close()
			if log, err = openRotatingFile(path, maxSize, backups); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := fmt.Fprintf(log, "line %03d of a flood of denied requests\n", i); err != nil {
			t.Fatal(err)
		}
	}
	log.Close()

	var lines []string
	for _, name := range []string{path + ".2", path + ".1", path} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 0 || len(data) > maxSize {
			t.Errorf("%s has %d bytes, want 1 to %d", filepath.Base(name), len(data), maxSize)
		}
		lines = append(lines, strings.Split(strings.TrimSpace(string(data)), "\n")...)
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Error("more backups than configured")
	}
	// The files hold the newest lines, in order and without gaps.
	for i, line := range lines {
		if want := fmt.Sprintf("line %03d", 100-len(lines)+i); !strings.HasPrefix(line, want) {
			t.Fatalf("line %d of %d is %q, want %q...", i, len(lines), line, want)
		}
	}
}
