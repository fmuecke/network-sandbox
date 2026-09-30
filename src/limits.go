// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"net"
	"sync"
	"time"
)

// The proxy runs outside the agent's account, so the agent must not be able
// to exhaust it. These limits bound the connections, goroutines and buffers
// that clients can hold.
const (
	maxConnections   = 256
	idleTimeout      = 15 * time.Minute // tunnel or transfer that makes no progress
	keepAliveTimeout = 2 * time.Minute  // client connection between two requests
)

// limitListener accepts at most cap(slots) connections at a time; further
// clients wait in the listen backlog. Each connection is an idleConn.
type limitListener struct {
	net.Listener
	idle      time.Duration
	slots     chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func newLimitListener(ln net.Listener, max int, idle time.Duration) *limitListener {
	return &limitListener{Listener: ln, idle: idle, slots: make(chan struct{}, max), closed: make(chan struct{})}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.closed:
		return nil, net.ErrClosed
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConn{
		Conn:    &idleConn{Conn: conn, idle: l.idle},
		release: sync.OnceFunc(func() { <-l.slots }),
	}, nil
}

func (l *limitListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

// limitedConn frees its slot in the limitListener when it is closed.
type limitedConn struct {
	net.Conn
	release func()
}

func (c *limitedConn) Close() error {
	c.release()
	return c.Conn.Close()
}

// idleConn fails reads and writes once the connection made no progress in
// either direction for the idle time, so a stalled or silent peer can't hold
// it forever. Progress in one direction keeps the other alive: a download
// sends nothing upstream for as long as it takes.
type idleConn struct {
	net.Conn
	idle time.Duration

	mu            sync.Mutex
	ownerDeadline bool // the owner set a read deadline of its own
}

func (c *idleConn) Read(b []byte) (int, error) {
	c.extend()
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	c.extend()
	return c.Conn.Write(b)
}

// extend moves the deadlines, also those of a read or write that is already
// waiting. A read deadline that the owner set takes precedence: net/http uses
// it to time out request headers and idle keep-alive connections, and to
// interrupt its own pending read.
func (c *idleConn) extend() {
	c.mu.Lock()
	defer c.mu.Unlock()
	deadline := time.Now().Add(c.idle)
	c.Conn.SetWriteDeadline(deadline)
	if !c.ownerDeadline {
		c.Conn.SetReadDeadline(deadline)
	}
}

func (c *idleConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ownerDeadline = !t.IsZero()
	return c.Conn.SetReadDeadline(t)
}

func (c *idleConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ownerDeadline = !t.IsZero()
	return c.Conn.SetDeadline(t)
}
