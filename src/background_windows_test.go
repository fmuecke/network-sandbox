// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBackgroundCommands builds the real executable, because "start" relaunches
// os.Executable(), which in a test is the test binary.
func TestBackgroundCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the executable")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "network-sandbox.exe")
	if out, err := exec.Command("go", "build", "-o", exe, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	config := filepath.Join(dir, "network-sandbox.ini")
	os.WriteFile(config, []byte(fmt.Sprintf("[network-sandbox]\nport=%s\nlogfile=%s\n[whitelist]\ngithub.com:443\n",
		addr[strings.LastIndex(addr, ":")+1:], filepath.Join(dir, "sandbox.log"))), 0o600)

	cmd := func(command string) (int, string) {
		c := exec.Command(exe, command, "-config", config)
		var out bytes.Buffer
		c.Stdout, c.Stderr = &out, &out
		err := c.Run()
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), out.String()
		} else if err != nil {
			t.Fatal(err)
		}
		return 0, out.String()
	}
	listening := func() bool {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
		}
		return err == nil
	}
	expect := func(command string, wantCode int, wantOut string) {
		t.Helper()
		code, out := cmd(command)
		if code != wantCode || !strings.Contains(out, wantOut) {
			t.Fatalf("%s: exit %d, output %q; want exit %d, output containing %q", command, code, out, wantCode, wantOut)
		}
	}
	t.Cleanup(func() { cmd("stop") })

	expect("status", exitNotRunning, "not running")
	expect("start", 0, "started in the background")
	if !listening() {
		t.Fatal("not listening after start")
	}
	expect("status", 0, "running (pid")
	expect("start", 1, "already running")
	pidBefore, _ := os.ReadFile(pidFilePath(config))

	expect("restart", 0, "started in the background")
	pidAfter, _ := os.ReadFile(pidFilePath(config))
	if bytes.Equal(pidBefore, pidAfter) {
		t.Error("restart kept the same process")
	}
	if !listening() {
		t.Fatal("not listening after restart")
	}

	expect("stop", 0, "stopped (pid")
	if listening() {
		t.Error("still listening after stop")
	}
	if _, err := os.Stat(pidFilePath(config)); !os.IsNotExist(err) {
		t.Error("PID file left behind")
	}
	expect("status", exitNotRunning, "not running")
	expect("stop", 0, "not running")

	// A stale PID file (here: our own, non-sandbox process) must not count as running.
	os.WriteFile(pidFilePath(config), []byte(fmt.Sprint(os.Getpid())), 0o600)
	expect("status", exitNotRunning, "not running")
}

func TestHelp(t *testing.T) {
	for _, arg := range []string{"-help", "-?", "/?", "/help", "/HELP", "-h", "--help"} {
		for _, args := range [][]string{{arg}, {"start", arg}} {
			var stderr bytes.Buffer
			if code := run(args, &stderr); code != 0 || !strings.Contains(stderr.String(), "-config <path>") {
				t.Errorf("%v: exit %d, output %q", args, code, stderr.String())
			}
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"launch"}, &stderr); code != 2 || !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("exit %d, %q", code, stderr.String())
	}
	if code := run([]string{"start", "extra"}, &stderr); code != 2 {
		t.Errorf("extra argument: exit %d", code)
	}
}
