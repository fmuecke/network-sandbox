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
	config := filepath.Join(dir, "background.json")
	os.WriteFile(config, []byte(fmt.Sprintf(`{"port":%s,"logfile":%q,"whitelist":["github.com:443"]}`,
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

	// Without -config, status lists every proxy, also one that runs in the
	// console with the default config, but no other program of the same name.
	ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	consoleAddr := ln.Addr().String()
	ln.Close()
	os.WriteFile(filepath.Join(dir, defaultConfigName), []byte(fmt.Sprintf(`{"port":%s,"logfile":%q,"whitelist":["github.com:443"]}`,
		consoleAddr[strings.LastIndex(consoleAddr, ":")+1:], filepath.Join(dir, "console.log"))), 0o600)
	console := exec.Command(exe)
	if err := console.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { console.Process.Kill() })
	cmdExe, err := os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
	if err != nil {
		t.Fatal(err)
	}
	impostorExe := filepath.Join(t.TempDir(), "network-sandbox.exe")
	os.WriteFile(impostorExe, cmdExe, 0o700)
	impostor := exec.Command(impostorExe, "/k")
	if _, err := impostor.StdinPipe(); err != nil { // cmd runs until its stdin closes
		t.Fatal(err)
	}
	if err := impostor.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		impostor.Process.Kill()
		impostor.Wait()
	})
	// statusLine returns the line of "status" about the proxy on addr, or "".
	statusLine := func(addr string) string {
		out, _ := exec.Command(exe, "status").CombinedOutput()
		if strings.Contains(string(out), fmt.Sprintf("(pid %d)", impostor.Process.Pid)) {
			t.Errorf("status lists a process that is no proxy:\n%s", out)
		}
		for line := range strings.Lines(string(out)) {
			if strings.Contains(line, "running (pid") && strings.Contains(line, " on "+addr+" ") {
				return strings.TrimSpace(line)
			}
		}
		return ""
	}
	if line := statusLine(addr); !strings.HasSuffix(line, "-config "+config) {
		t.Errorf("status without -config: background proxy: %q", line)
	}
	consoleLine := ""
	for deadline := time.Now().Add(5 * time.Second); consoleLine == "" && time.Now().Before(deadline); {
		consoleLine = statusLine(consoleAddr)
	}
	if !strings.HasSuffix(consoleLine, defaultConfigName) {
		t.Errorf("status without -config: console proxy with the default config: %q", consoleLine)
	}
	console.Process.Kill()
	console.Wait()
	if line := statusLine(consoleAddr); line != "" {
		t.Errorf("status without -config lists a stopped proxy: %q", line)
	}

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

	// A stale PID file must not count as running: here, the PID now belongs to
	// a process that was created at another time.
	os.WriteFile(pidFilePath(config), []byte(fmt.Sprintf("%d 1\n", os.Getpid())), 0o600)
	expect("status", exitNotRunning, "not running")
	expect("stop", 0, "not running")

	// Concurrent starts of one config must not both start a proxy.
	codes := make(chan int)
	for range 2 {
		go func() {
			code, _ := cmd("start")
			codes <- code
		}()
	}
	if a, b := <-codes, <-codes; a+b != 1 {
		t.Errorf("concurrent starts: exit codes %d and %d, want one 0 and one 1", a, b)
	}
	expect("status", 0, "running (pid")
	expect("stop", 0, "stopped (pid")
	if _, err := os.Stat(pidFilePath(config) + ".lock"); !os.IsNotExist(err) {
		t.Error("lock file left behind")
	}
}

func TestPIDFilePath(t *testing.T) {
	if pidFilePath(`C:\dir\policy.json`) == pidFilePath(`C:\dir\policy.conf`) {
		t.Error("configs that differ in the extension share a PID file")
	}
	if config := `C:\dir\policy.pid`; pidFilePath(config) == config {
		t.Error("the PID file of a config named .pid is the config itself")
	}
}

func TestCommandLineArgs(t *testing.T) {
	for in, want := range map[string]string{
		`"C:\my dir\network-sandbox.exe" -config "C:\my dir\a.json"`: `-config "C:\my dir\a.json"`,
		`C:\dir\network-sandbox.exe -config C:\dir\a.json`:           `-config C:\dir\a.json`,
		`"C:\dir\network-sandbox.exe"`:                               "",
		`network-sandbox.exe`:                                        "",
		``:                                                           "",
	} {
		if got := commandLineArgs(in); got != want {
			t.Errorf("commandLineArgs(%q) = %q, want %q", in, got, want)
		}
	}
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
