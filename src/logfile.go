// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"sync"
)

// Every request is logged, also denied ones, so without a bound a client
// could fill the disk. The log takes at most (logBackups+1) * maxLogSize.
const (
	maxLogSize = 10 << 20
	logBackups = 3
)

// rotatingFile is an append-only log file. When a write would grow it beyond
// maxSize, the file becomes <name>.1, older files move up to <name>.<backups>,
// and the oldest is deleted.
type rotatingFile struct {
	path    string
	maxSize int64
	backups int

	mu   sync.Mutex
	file *os.File
	size int64
}

func openRotatingFile(path string, maxSize int64, backups int) (*rotatingFile, error) {
	r := &rotatingFile{path: path, maxSize: maxSize, backups: backups}
	if err := r.open(os.O_APPEND); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) open(mode int) error {
	f, err := os.OpenFile(r.path, mode|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.file, r.size = f, info.Size()
	return nil
}

func (r *rotatingFile) Name() string { return r.path }

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size > 0 && r.size+int64(len(p)) > r.maxSize {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.file.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) rotate() error {
	r.file.Close()
	for i := r.backups; i > 1; i-- {
		os.Rename(r.backup(i-1), r.backup(i)) // fails while there are fewer backups
	}
	mode := os.O_APPEND
	if err := os.Rename(r.path, r.backup(1)); err != nil {
		mode = os.O_TRUNC // keep the size bound rather than the old lines
	}
	return r.open(mode)
}

func (r *rotatingFile) backup(i int) string {
	return fmt.Sprintf("%s.%d", r.path, i)
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.file.Close()
}
