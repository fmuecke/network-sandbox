// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Background mode: "start" launches this executable detached from the console
// and records its PID next to the config; "stop" terminates that process.
// There is deliberately no network control endpoint: the agent could use it.

const (
	exitNotRunning = 3

	detachedProcess                = 0x00000008
	processQueryLimitedInformation = 0x1000
	stillActive                    = 259
	startTimeout                   = 5 * time.Second
)

var procQueryFullProcessImageName = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryFullProcessImageNameW")

func start(configPath string, stderr io.Writer) int {
	if pid := runningPID(configPath); pid != 0 {
		return fail(stderr, fmt.Errorf("already running (pid %d)", pid))
	}
	// Check everything the background process needs here, where errors are
	// visible; the detached process has no console to report them.
	cfg, err := loadConfig(configPath)
	if err != nil {
		return fail(stderr, err)
	}
	logFile, err := openLog(cfg)
	if err != nil {
		return fail(stderr, err)
	}
	logPath := logFile.Name()
	logFile.Close()
	addr := listenAddr(cfg)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fail(stderr, err)
	}
	ln.Close()

	exe, err := os.Executable()
	if err != nil {
		return fail(stderr, err)
	}
	cmd := exec.Command(exe, "-config", configPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: detachedProcess | syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return fail(stderr, err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	if err := waitListening(addr, exited); err != nil {
		cmd.Process.Kill()
		return fail(stderr, fmt.Errorf("background process failed to start: %w; run without a command to see why", err))
	}
	if err := os.WriteFile(pidFilePath(configPath), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		cmd.Process.Kill()
		return fail(stderr, err)
	}
	fmt.Fprintf(stderr, "network-sandbox: started in the background (pid %d), listening on %s, logging to %s\n",
		cmd.Process.Pid, addr, logPath)
	return 0
}

func waitListening(addr string, exited <-chan error) error {
	deadline := time.Now().Add(startTimeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			if err == nil {
				err = errors.New("exited")
			}
			return err
		default:
		}
		if conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("not listening on %s after %s", addr, startTimeout)
}

// stop terminates the background process. Stopping one that isn't running succeeds.
func stop(configPath string, stderr io.Writer) int {
	pidFile := pidFilePath(configPath)
	pid := runningPID(configPath)
	if pid == 0 {
		os.Remove(pidFile) // stale
		fmt.Fprintln(stderr, "network-sandbox: not running")
		return 0
	}
	if err := terminate(pid); err != nil {
		return fail(stderr, fmt.Errorf("cannot stop pid %d: %w", pid, err))
	}
	os.Remove(pidFile)
	fmt.Fprintf(stderr, "network-sandbox: stopped (pid %d)\n", pid)
	return 0
}

func status(configPath string, stderr io.Writer) int {
	pid := runningPID(configPath)
	if pid == 0 {
		fmt.Fprintln(stderr, "network-sandbox: not running")
		return exitNotRunning
	}
	fmt.Fprintf(stderr, "network-sandbox: running (pid %d)\n", pid)
	return 0
}

// pidFilePath is the config path with a .pid extension, so instances with
// different configs don't collide.
func pidFilePath(configPath string) string {
	return strings.TrimSuffix(configPath, filepath.Ext(configPath)) + ".pid"
}

// runningPID returns the PID from the PID file if that process is still a
// running network-sandbox, and 0 otherwise (no file, or a stale or reused PID).
func runningPID(configPath string) int {
	data, err := os.ReadFile(pidFilePath(configPath))
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 || !isRunningSandbox(pid) {
		return 0
	}
	return pid
}

func isRunningSandbox(pid int) bool {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil || code != stillActive {
		return false
	}
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if r, _, _ := procQueryFullProcessImageName.Call(uintptr(h), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return false
	}
	own, err := os.Executable()
	if err != nil {
		return false
	}
	// Compare names, not full paths, so a copy of the exe elsewhere can still stop it.
	return strings.EqualFold(filepath.Base(syscall.UTF16ToString(buf[:size])), filepath.Base(own))
}

func terminate(pid int) error {
	h, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE|syscall.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	if err := syscall.TerminateProcess(h, 1); err != nil {
		return err
	}
	if ev, err := syscall.WaitForSingleObject(h, 5000); err != nil || ev != syscall.WAIT_OBJECT_0 {
		return errors.New("process did not exit")
	}
	return nil
}
