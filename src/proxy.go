// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"
)

const (
	dialTimeout       = 10 * time.Second
	readHeaderTimeout = 30 * time.Second
)

// Proxy is an HTTP proxy that only reaches whitelisted destinations.
type Proxy struct {
	whitelist *Whitelist
	log       *slog.Logger
	dialer    net.Dialer
	forward   *httputil.ReverseProxy

	mu      sync.Mutex
	closed  bool
	tunnels map[net.Conn]bool
}

// record collects what gets logged about one request or tunnel.
type record struct {
	target   string
	decision string
	status   int
	up, down int64
	err      error
}

type recordKey struct{}

func NewProxy(wl *Whitelist, log *slog.Logger) *Proxy {
	p := &Proxy{
		whitelist: wl,
		log:       log,
		dialer:    net.Dialer{Timeout: dialTimeout},
		tunnels:   map[net.Conn]bool{},
	}
	p.forward = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			for k := range pr.Out.Header {
				if strings.HasPrefix(k, "Proxy-") {
					pr.Out.Header.Del(k)
				}
			}
		},
		Transport: &http.Transport{
			Proxy:           nil, // never chain to a proxy from the environment
			DialContext:     p.dialer.DialContext,
			IdleConnTimeout: 90 * time.Second,
		},
		FlushInterval: -1, // stream responses (e.g. server-sent events) without delay
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			rec := r.Context().Value(recordKey{}).(*record)
			rec.err = err
			http.Error(w, "network-sandbox: upstream error: "+err.Error(), http.StatusBadGateway)
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &record{decision: "deny"}
	if r.Method == http.MethodConnect {
		p.tunnel(w, r, rec)
	} else {
		p.forwardHTTP(w, r, rec)
	}
	attrs := []any{
		"client", r.RemoteAddr,
		"method", r.Method,
		"target", rec.target,
		"decision", rec.decision,
		"status", rec.status,
		"bytes_up", rec.up,
		"bytes_down", rec.down,
		"duration", time.Since(start),
	}
	if rec.err != nil {
		attrs = append(attrs, "error", rec.err)
	}
	p.log.Info("request", attrs...)
}

func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request, rec *record) {
	rec.target = r.Host
	host, port, err := splitHostPort(r.Host)
	if err != nil {
		p.reject(w, rec, http.StatusBadRequest, "network-sandbox: invalid CONNECT target")
		return
	}
	target, ok := p.whitelist.Check(host, port)
	if !ok {
		p.reject(w, rec, http.StatusForbidden, fmt.Sprintf("network-sandbox: %s not in whitelist", r.Host))
		return
	}
	rec.target, rec.decision = target, "allow"

	upstream, err := p.dialer.DialContext(r.Context(), "tcp", target)
	if err != nil {
		rec.err = err
		p.reject(w, rec, http.StatusBadGateway, "network-sandbox: cannot reach "+target)
		return
	}
	client, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		upstream.Close()
		rec.err = err
		p.reject(w, rec, http.StatusInternalServerError, "network-sandbox: cannot open tunnel")
		return
	}
	client.SetDeadline(time.Time{})
	if !p.track(client, upstream) {
		client.Close()
		upstream.Close()
		rec.err = net.ErrClosed
		return
	}
	defer p.untrack(client, upstream)

	rec.status = http.StatusOK
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		rec.err = err
		return
	}
	// When either direction ends, close both: the tunnel is done.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rec.up, _ = io.Copy(upstream, buf.Reader) // buf.Reader holds bytes already read from the client
		client.Close()
		upstream.Close()
	}()
	down, _ := io.Copy(client, upstream)
	client.Close()
	upstream.Close()
	wg.Wait()
	rec.down = down
}

func (p *Proxy) forwardHTTP(w http.ResponseWriter, r *http.Request, rec *record) {
	rec.target = r.URL.Host
	if r.URL.Scheme != "http" || r.URL.Host == "" {
		p.reject(w, rec, http.StatusBadRequest,
			"network-sandbox: not a proxy request; use CONNECT or an absolute http:// URL")
		return
	}
	portStr := r.URL.Port()
	if portStr == "" {
		portStr = "80"
	}
	port, err := parsePort(portStr)
	if err != nil {
		p.reject(w, rec, http.StatusBadRequest, "network-sandbox: invalid port")
		return
	}
	rec.target = net.JoinHostPort(r.URL.Hostname(), portStr)
	target, ok := p.whitelist.Check(r.URL.Hostname(), port)
	if !ok {
		p.reject(w, rec, http.StatusForbidden, fmt.Sprintf("network-sandbox: %s not in whitelist", rec.target))
		return
	}
	rec.target, rec.decision = target, "allow"
	if p.log.Enabled(r.Context(), slog.LevelDebug) {
		p.log.Debug("request headers", "target", target, "url", r.URL.String(), "headers", redactHeaders(r.Header))
	}

	r.URL.Host = target // dial exactly what was matched
	body := &countingReader{r: r.Body}
	r.Body = body
	cw := &countingWriter{ResponseWriter: w}
	p.forward.ServeHTTP(cw, r.WithContext(context.WithValue(r.Context(), recordKey{}, rec)))
	rec.status, rec.up, rec.down = cw.status, body.n, cw.n
}

func (p *Proxy) reject(w http.ResponseWriter, rec *record, status int, msg string) {
	rec.status = status
	http.Error(w, msg, status)
}

func (p *Proxy) track(conns ...net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	for _, c := range conns {
		p.tunnels[c] = true
	}
	return true
}

func (p *Proxy) untrack(conns ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range conns {
		delete(p.tunnels, c)
	}
}

// CloseTunnels closes all open tunnels and refuses new ones.
func (p *Proxy) CloseTunnels() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for c := range p.tunnels {
		c.Close()
	}
}

var secretHeaders = map[string]bool{
	"Authorization":       true,
	"Proxy-Authorization": true,
	"Cookie":              true,
	"X-Api-Key":           true,
}

func redactHeaders(h http.Header) http.Header {
	c := h.Clone()
	for k := range c {
		if secretHeaders[k] {
			c[k] = []string{"[redacted]"}
		}
	}
	return c
}

type countingReader struct {
	r io.ReadCloser
	n int64
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n += int64(n)
	return n, err
}

func (c *countingReader) Close() error { return c.r.Close() }

type countingWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (c *countingWriter) WriteHeader(status int) {
	if c.status == 0 || c.status < 200 {
		c.status = status
	}
	c.ResponseWriter.WriteHeader(status)
}

func (c *countingWriter) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	n, err := c.ResponseWriter.Write(b)
	c.n += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach Flush and Hijack.
func (c *countingWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }
