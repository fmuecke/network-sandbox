// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	dialTimeout       = 10 * time.Second
	readHeaderTimeout = 30 * time.Second
)

// Proxy is an HTTP proxy that only reaches allowed destinations.
type Proxy struct {
	allowlist    *Allowlist
	allowPrivate bool // hostnames may resolve to non-public addresses
	idleTimeout  time.Duration
	log          *slog.Logger
	forward      *httputil.ReverseProxy

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

func NewProxy(allowlist *Allowlist, allowPrivate bool, log *slog.Logger) *Proxy {
	p := &Proxy{
		allowlist:    allowlist,
		allowPrivate: allowPrivate,
		idleTimeout:  idleTimeout,
		log:          log,
		tunnels:      map[net.Conn]bool{},
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
			DialContext:     p.dial,
			IdleConnTimeout: 90 * time.Second,
		},
		FlushInterval: -1, // stream responses (e.g. server-sent events) without delay
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			rec := r.Context().Value(recordKey{}).(*record)
			rec.err = err
			if errors.Is(err, errNonPublic) {
				rec.decision = "deny"
				http.Error(w, nonPublicMessage(rec.target), http.StatusForbidden)
				return
			}
			http.Error(w, "network-sandbox: upstream error: "+err.Error(), http.StatusBadGateway)
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := &record{decision: "deny"}
	// Deferred, so that a transfer that net/http aborts with a panic is logged too.
	defer p.logRequest(r, rec, time.Now())
	if r.Method == http.MethodConnect {
		p.tunnel(w, r, rec)
	} else {
		p.forwardHTTP(w, r, rec)
	}
}

func (p *Proxy) logRequest(r *http.Request, rec *record, start time.Time) {
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
	target, ok := p.allowlist.Check(host, port)
	if !ok {
		p.reject(w, rec, http.StatusForbidden, fmt.Sprintf("network-sandbox: %s not allowed", r.Host))
		return
	}
	rec.target, rec.decision = target, "allow"

	upstream, err := p.dial(r.Context(), "tcp", target)
	if errors.Is(err, errNonPublic) {
		rec.decision, rec.err = "deny", err
		p.reject(w, rec, http.StatusForbidden, nonPublicMessage(target))
		return
	}
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
	target, ok := p.allowlist.Check(r.URL.Hostname(), port)
	if !ok {
		p.reject(w, rec, http.StatusForbidden, fmt.Sprintf("network-sandbox: %s not allowed", rec.target))
		return
	}
	rec.target, rec.decision = target, "allow"
	if p.log.Enabled(r.Context(), slog.LevelDebug) {
		p.log.Debug("request headers", "target", target, "url", redactURL(r.URL), "headers", redactHeaders(r.Header))
	}

	r.URL.Host = target // dial exactly what was matched
	body := &countingReader{r: r.Body}
	r.Body = body
	cw := &countingWriter{ResponseWriter: w}
	defer func() { rec.status, rec.up, rec.down = cw.status, body.n, cw.n }()
	p.forward.ServeHTTP(cw, r.WithContext(context.WithValue(r.Context(), recordKey{}, rec)))
}

var errNonPublic = errors.New("not a public address")

func nonPublicMessage(target string) string {
	return fmt.Sprintf("network-sandbox: %s resolves to a non-public address", target)
}

// dial connects to an allowed target. A hostname is resolved here, by the
// system resolver, and must lead to a public address: otherwise a DNS answer
// could point an allowed name at loopback or the local network. An IP literal
// was allowed as such and is dialed as it is.
func (p *Proxy) dial(ctx context.Context, network, target string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: dialTimeout}
	host, _, _ := net.SplitHostPort(target)
	if _, err := netip.ParseAddr(host); err != nil && !p.allowPrivate {
		// Control sees the address of each connection attempt, so it checks
		// exactly what gets connected, whatever the resolver answers.
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			if ap, err := netip.ParseAddrPort(address); err != nil || !isPublic(ap.Addr()) {
				return errNonPublic
			}
			return nil
		}
	}
	conn, err := dialer.DialContext(ctx, network, target)
	if err != nil {
		return nil, err
	}
	return &idleConn{Conn: conn, idle: p.idleTimeout}, nil
}

// nonPublic lists address ranges that aren't reachable on the internet, in
// addition to those that netip.Addr classifies itself.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     // this network
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved
	netip.MustParsePrefix("fec0::/10"),     // site-local (deprecated)
}

var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// isPublic reports whether addr is a public unicast address: not loopback,
// private, link-local, multicast, unspecified or otherwise reserved.
func isPublic(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	if nat64.Contains(addr) { // stands for the IPv4 address in its last four bytes
		b := addr.As16()
		addr = netip.AddrFrom4([4]byte(b[12:]))
	}
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, prefix := range nonPublic {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
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

// safeHeaders are the headers whose values the debug log shows. All other
// values are redacted: credentials travel in too many headers to list them.
var safeHeaders = map[string]bool{
	"Accept":          true,
	"Accept-Encoding": true,
	"Content-Length":  true,
	"Content-Type":    true,
	"User-Agent":      true,
}

func redactHeaders(h http.Header) http.Header {
	c := h.Clone()
	for k := range c {
		if !safeHeaders[k] {
			c[k] = []string{"[redacted]"}
		}
	}
	return c
}

// redactURL returns the URL without user information and query, which often
// carry credentials (signed URLs, access tokens).
func redactURL(u *url.URL) string {
	c := *u
	c.User = nil
	if c.RawQuery != "" {
		c.RawQuery = "[redacted]"
	}
	return c.String()
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
