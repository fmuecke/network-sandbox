// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Background mode: "start" launches this executable detached from the console
// and records the process next to the config; "stop" terminates that process.
// There is deliberately no network control endpoint: the agent could use it.

const (
	exitNotRunning = 3

	detachedProcess                = 0x00000008
	processQueryLimitedInformation = 0x1000
	processCommandLineInformation  = 60
	tcpTableOwnerPIDListener       = 3
	fileFlagDeleteOnClose          = 0x04000000
	errorSharingViolation          = syscall.Errno(32)
	startTimeout                   = 5 * time.Second
	lockTimeout                    = 30 * time.Second
)

var (
	procQueryFullProcessImageName = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryFullProcessImageNameW")
	procNtQueryInformationProcess = syscall.NewLazyDLL("ntdll.dll").NewProc("NtQueryInformationProcess")
	procGetExtendedTcpTable       = syscall.NewLazyDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
)

// start, stop and restart take the -config-json config as inline, or nil for
// a config file. An inline config is stored at configPath while its proxy runs.
// The file is only ours if the PID file next to it says so (inlineOwned): a
// file of that name might also be a config that someone wrote.

func start(configPath string, inline []byte, stderr io.Writer) int {
	return locked(configPath, inline, stderr, func() int { return startBackground(configPath, inline, stderr) })
}

func stop(configPath string, inline []byte, stderr io.Writer) int {
	return locked(configPath, inline, stderr, func() int { return stopBackground(configPath, inline, stderr) })
}

func restart(configPath string, inline []byte, stderr io.Writer) int {
	return locked(configPath, inline, stderr, func() int {
		if code := stopBackground(configPath, inline, stderr); code != 0 {
			return code
		}
		return startBackground(configPath, inline, stderr)
	})
}

// locked runs a command while no other start, stop or restart of the same
// config runs. Otherwise two of them could both find no proxy and start one,
// or act on a PID file that the other is about to replace. With an inline
// config, it also refuses to act on a proxy that was started with -config.
func locked(configPath string, inline []byte, stderr io.Writer, command func() int) int {
	// The lock is a file that is held open without sharing. Windows deletes it
	// when the handle closes, also if this process dies.
	lockFile := pidFilePath(configPath) + ".lock"
	name, err := syscall.UTF16PtrFromString(lockFile)
	if err != nil {
		return fail(stderr, err)
	}
	deadline := time.Now().Add(lockTimeout)
	for {
		h, err := syscall.CreateFile(name, syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_ALWAYS,
			syscall.FILE_ATTRIBUTE_NORMAL|fileFlagDeleteOnClose, 0)
		if err == nil {
			defer syscall.CloseHandle(h)
			if _, err := os.Stat(pidFilePath(configPath)); inline != nil && err == nil && !inlineOwned(configPath) {
				return fail(stderr, fmt.Errorf("the proxy of %s was started with -config; use -config", configPath))
			}
			return command()
		}
		if err != errorSharingViolation {
			return fail(stderr, fmt.Errorf("cannot lock %s: %w", lockFile, err))
		}
		if time.Now().After(deadline) {
			return fail(stderr, fmt.Errorf("another start or stop of this config is in progress (%s)", lockFile))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func startBackground(configPath string, inline []byte, stderr io.Writer) (code int) {
	running, err := openBackground(configPath, 0)
	if err != nil {
		return fail(stderr, err)
	}
	if running != nil {
		syscall.CloseHandle(running.process)
		return fail(stderr, fmt.Errorf("already running (pid %d)", running.pid))
	}
	if inline != nil {
		if inlineOwned(configPath) { // left by a -config-json proxy that is gone
			os.Remove(configPath)
			os.Remove(pidFilePath(configPath))
		}
		if err := writeNewFile(configPath, inline); errors.Is(err, fs.ErrExist) {
			return fail(stderr, fmt.Errorf("%s exists, but -config-json didn't store it; use -config, or remove the file", configPath))
		} else if err != nil {
			return fail(stderr, err)
		}
		defer func() {
			if code != 0 {
				os.Remove(configPath)
			}
		}()
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
	// Until cmd.Wait, the PID can't be reused: this is the time of the child.
	created, err := creationTime(cmd.Process.Pid)
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	if err == nil {
		err = waitListening(cmd.Process.Pid, addr, exited)
	}
	if err != nil {
		cmd.Process.Kill()
		return fail(stderr, fmt.Errorf("background process failed to start: %w; run without a command to see why", err))
	}
	pidFile := fmt.Sprintf("%d %d\n", cmd.Process.Pid, created)
	if inline != nil {
		pidFile = fmt.Sprintf("%d %d %s\n", cmd.Process.Pid, created, inlineMarker)
	}
	if err := os.WriteFile(pidFilePath(configPath), []byte(pidFile), 0o600); err != nil {
		cmd.Process.Kill()
		return fail(stderr, err)
	}
	fmt.Fprintf(stderr, "network-sandbox: started in the background (pid %d), listening on %s, logging to %s\n",
		cmd.Process.Pid, addr, logFile.Name())
	return 0
}

// waitListening waits until the process itself listens on addr. Connecting to
// addr would not tell: another process could have taken the port.
func waitListening(pid int, addr string, exited <-chan error) error {
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
		if listeners, err := loopbackListeners(); err != nil {
			return err
		} else if listeners[pid] == addr {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("not listening on %s after %s", addr, startTimeout)
}

// stopBackground terminates the background process. Stopping one that isn't
// running succeeds.
func stopBackground(configPath string, inline []byte, stderr io.Writer) int {
	running, err := openBackground(configPath, syscall.PROCESS_TERMINATE)
	if err != nil {
		return fail(stderr, err)
	}
	owned := inline != nil && inlineOwned(configPath)
	removeFiles := func() {
		os.Remove(pidFilePath(configPath))
		if owned {
			os.Remove(configPath)
		}
	}
	if running == nil {
		removeFiles() // stale
		fmt.Fprintln(stderr, "network-sandbox: not running")
		return 0
	}
	defer syscall.CloseHandle(running.process)
	if err := terminate(running.process); err != nil {
		return fail(stderr, fmt.Errorf("cannot stop pid %d: %w", running.pid, err))
	}
	removeFiles()
	fmt.Fprintf(stderr, "network-sandbox: stopped (pid %d)\n", running.pid)
	return 0
}

// status reports whether the background proxy of this config is running.
func status(configPath string, stderr io.Writer) int {
	running, err := openBackground(configPath, 0)
	if err != nil {
		return fail(stderr, err)
	}
	if running == nil {
		fmt.Fprintln(stderr, "network-sandbox: not running")
		return exitNotRunning
	}
	syscall.CloseHandle(running.process)
	fmt.Fprintf(stderr, "network-sandbox: running (pid %d) on %s -config %s\n", running.pid, running.listen, configPath)
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
	// A proxy takes no argument but -config or -config-json.
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

// pidFilePath is the config path plus ".pid", so every config has its own PID
// file and none can be mistaken for one.
func pidFilePath(configPath string) string {
	return configPath + ".pid"
}

// inlineMarker ends the PID file of a proxy whose config -config-json stored.
const inlineMarker = "inline"

// inlineOwned reports whether the config at configPath was stored by
// -config-json, and so may be replaced or deleted.
func inlineOwned(configPath string) bool {
	data, err := os.ReadFile(pidFilePath(configPath))
	fields := strings.Fields(string(data))
	return err == nil && len(fields) == 3 && fields[2] == inlineMarker
}

// background is a running background proxy.
type background struct {
	process syscall.Handle
	pid     int
	listen  string
}

// openBackground opens the background proxy of the config with the given
// access rights, so that the caller acts on the very process that was
// checked. It returns nil if no proxy runs: there is no PID file, or the
// process it names is gone.
//
// The PID file holds the PID and the creation time of the process, which
// together identify it; the PID alone could meanwhile belong to another
// process. The process must also look like a proxy, so that a forged PID
// file can't direct "stop" at an arbitrary process.
func openBackground(configPath string, access uint32) (*background, error) {
	data, err := os.ReadFile(pidFilePath(configPath))
	if err != nil {
		return nil, nil
	}
	var pid int
	var created int64
	if _, err := fmt.Sscanf(string(data), "%d %d", &pid, &created); err != nil {
		return nil, nil
	}
	proxies, err := runningProxies()
	if err != nil {
		return nil, err
	}
	listen, isProxy := proxies[pid]
	if !isProxy {
		return nil, nil
	}
	process, err := syscall.OpenProcess(access|processQueryLimitedInformation|syscall.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("cannot access pid %d: %w", pid, err)
	}
	if processCreated, err := handleCreationTime(process); err != nil || processCreated != created || hasExited(process) {
		syscall.CloseHandle(process)
		return nil, nil
	}
	return &background{process, pid, listen}, nil
}

// creationTime returns when the process was created, in nanoseconds since 1970.
func creationTime(pid int) (int64, error) {
	process, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(process)
	return handleCreationTime(process)
}

func handleCreationTime(process syscall.Handle) (int64, error) {
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(process, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return created.Nanoseconds(), nil
}

func hasExited(process syscall.Handle) bool {
	event, _ := syscall.WaitForSingleObject(process, 0)
	return event == syscall.WAIT_OBJECT_0
}

func terminate(process syscall.Handle) error {
	if err := syscall.TerminateProcess(process, 1); err != nil {
		return err
	}
	if ev, err := syscall.WaitForSingleObject(process, 5000); err != nil || ev != syscall.WAIT_OBJECT_0 {
		return errors.New("process did not exit")
	}
	return nil
}
