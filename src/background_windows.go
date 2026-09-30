// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	processCommandLineInformation  = 60
	tcpTableOwnerPIDListener       = 3
	startTimeout                   = 5 * time.Second
)

var (
	procQueryFullProcessImageName = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryFullProcessImageNameW")
	procNtQueryInformationProcess = syscall.NewLazyDLL("ntdll.dll").NewProc("NtQueryInformationProcess")
	procGetExtendedTcpTable       = syscall.NewLazyDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
)

func start(configPath string, stderr io.Writer) int {
	if pid, _ := runningPID(configPath); pid != 0 {
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
	pid, _ := runningPID(configPath)
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

// status reports whether the background proxy of this config is running.
func status(configPath string, stderr io.Writer) int {
	pid, listen := runningPID(configPath)
	if pid == 0 {
		fmt.Fprintln(stderr, "network-sandbox: not running")
		return exitNotRunning
	}
	fmt.Fprintf(stderr, "network-sandbox: running (pid %d) on %s -config %s\n", pid, listen, configPath)
	return 0
}

// statusAll lists every running proxy with its listen address and config. It
// reads the process list, not the PID files, so it also finds proxies that run
// in a console.
func statusAll(stderr io.Writer) int {
	proxies, err := runningProxies()
	if err != nil {
		return fail(stderr, err)
	}
	if len(proxies) == 0 {
		fmt.Fprintln(stderr, "network-sandbox: not running")
		return exitNotRunning
	}
	for _, pid := range slices.Sorted(maps.Keys(proxies)) {
		fmt.Fprintln(stderr, strings.TrimSpace(fmt.Sprintf("network-sandbox: running (pid %d) on %s %s", pid, proxies[pid], configArg(pid))))
	}
	return 0
}

// runningProxies returns the listen address of every running proxy by PID. A
// proxy is another process that was started from an executable with this one's
// name and listens on loopback. The name alone also matches unrelated programs
// and network-sandbox commands like this one. Names are compared, not full
// paths, so a copy of the exe elsewhere can still find and stop a proxy.
func runningProxies() (map[int]string, error) {
	own, err := os.Executable()
	if err != nil {
		return nil, err
	}
	listeners, err := loopbackListeners()
	if err != nil {
		return nil, err
	}
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snapshot)
	proxies := map[int]string{}
	entry := syscall.ProcessEntry32{Size: uint32(unsafe.Sizeof(syscall.ProcessEntry32{}))}
	for err := syscall.Process32First(snapshot, &entry); err == nil; err = syscall.Process32Next(snapshot, &entry) {
		pid := int(entry.ProcessID)
		listen, listens := listeners[pid]
		if listens && pid != os.Getpid() && strings.EqualFold(syscall.UTF16ToString(entry.ExeFile[:]), filepath.Base(own)) {
			proxies[pid] = listen
		}
	}
	return proxies, nil
}

// loopbackListeners returns, by PID, the 127.0.0.1 address that a process
// accepts TCP connections on.
func loopbackListeners() (map[int]string, error) {
	// The call fills in a MIB_TCPTABLE_OWNER_PID: the number of rows, then rows
	// of six uint32: state, local address, local port, remote address, remote
	// port, PID. Addresses and ports are in network byte order.
	const rowSize = 6 * 4
	buf := make([]byte, 1<<14)
	for {
		size := uint32(len(buf))
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0, syscall.AF_INET, tcpTableOwnerPIDListener, 0)
		if r == 0 {
			break
		}
		if syscall.Errno(r) != syscall.ERROR_INSUFFICIENT_BUFFER {
			return nil, fmt.Errorf("GetExtendedTcpTable: %w", syscall.Errno(r))
		}
		buf = make([]byte, size)
	}
	listeners := map[int]string{}
	for i := range int(binary.NativeEndian.Uint32(buf)) {
		row := buf[4+i*rowSize:][:rowSize]
		if addr := netip.AddrFrom4([4]byte(row[4:8])); addr.IsLoopback() {
			pid := int(binary.NativeEndian.Uint32(row[20:]))
			listeners[pid] = netip.AddrPortFrom(addr, binary.BigEndian.Uint16(row[8:])).String()
		}
	}
	return listeners, nil
}

// configArg returns the -config argument that names the config of a running
// proxy, or "" if the process can't be inspected, e.g. because it belongs to
// another user.
func configArg(pid int) string {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return ""
	}
	defer syscall.CloseHandle(h)
	// A UNICODE_STRING, followed by room for the text it points to.
	commandLine := new(struct {
		length, maxLength uint16 // in bytes
		text              *uint16
		_                 [32768]uint16
	})
	if status, _, _ := procNtQueryInformationProcess.Call(uintptr(h), processCommandLineInformation,
		uintptr(unsafe.Pointer(commandLine)), unsafe.Sizeof(*commandLine), 0); status != 0 || commandLine.text == nil {
		return ""
	}
	// A proxy takes no argument but -config.
	if args := commandLineArgs(syscall.UTF16ToString(unsafe.Slice(commandLine.text, commandLine.length/2))); args != "" {
		return args
	}
	// Without it, the proxy uses the default config next to its exe.
	exe := make([]uint16, 32768)
	size := uint32(len(exe))
	if r, _, _ := procQueryFullProcessImageName.Call(uintptr(h), 0,
		uintptr(unsafe.Pointer(&exe[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return ""
	}
	return "-config " + filepath.Join(filepath.Dir(syscall.UTF16ToString(exe[:size])), defaultConfigName)
}

// commandLineArgs returns a command line without the program name.
func commandLineArgs(commandLine string) string {
	sep := " "
	if strings.HasPrefix(commandLine, `"`) {
		commandLine, sep = commandLine[1:], `"`
	}
	_, args, _ := strings.Cut(commandLine, sep)
	return strings.TrimSpace(args)
}

// pidFilePath is the config path with a .pid extension, so instances with
// different configs don't collide.
func pidFilePath(configPath string) string {
	return strings.TrimSuffix(configPath, filepath.Ext(configPath)) + ".pid"
}

// runningPID returns the PID from the PID file and the listen address of that
// process if it is still a running proxy, and 0 otherwise (no file, or a stale
// or reused PID).
func runningPID(configPath string) (pid int, listen string) {
	data, err := os.ReadFile(pidFilePath(configPath))
	if err != nil {
		return 0, ""
	}
	pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, ""
	}
	proxies, _ := runningProxies()
	listen, running := proxies[pid]
	if !running {
		return 0, ""
	}
	return pid, listen
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
