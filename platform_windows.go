//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	shell32                   = syscall.NewLazyDLL("shell32.dll")
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procIsUserAnAdmin         = shell32.NewProc("IsUserAnAdmin")
	procShellExecuteW         = shell32.NewProc("ShellExecuteW")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
)

// isAdmin reports whether the current process token is elevated.
func isAdmin() bool {
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

// relaunchElevated starts this executable again with the "runas" verb (UAC prompt).
// The new process runs in its own console window; this process does not wait for it.
func relaunchElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	quoted := make([]string, 0, len(args))
	for _, a := range args {
		quoted = append(quoted, syscall.EscapeArg(a))
	}
	params, _ := syscall.UTF16PtrFromString(strings.Join(quoted, " "))
	const swShowNormal = 1
	r, _, callErr := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)),
		0,
		swShowNormal,
	)
	// ShellExecute returns a value > 32 on success.
	if r <= 32 {
		return fmt.Errorf("elevation was cancelled or denied (ShellExecute code %d: %v)", r, callErr)
	}
	return nil
}

// ownsConsole is true when this process is the only one attached to its console, i.e. it was
// started by double-click or by a UAC relaunch rather than from an existing shell.
func ownsConsole() bool {
	var list [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&list[0])), uintptr(len(list)))
	return n == 1
}

func pauseIfOwnConsole() {
	if !ownsConsole() {
		return
	}
	fmt.Print("\nPress Enter to close this window...")
	_, _ = stdin.ReadString('\n')
}

func processRunning(image string) bool {
	tl := filepath.Join(os.Getenv("SystemRoot"), "System32", "tasklist.exe")
	out, err := exec.Command(tl, "/FI", "IMAGENAME eq "+image, "/NH").Output()
	if err != nil {
		return true // cannot tell - do not nag
	}
	return strings.Contains(strings.ToUpper(string(out)), strings.ToUpper(image))
}

func outlookRunning() bool { return processRunning("OUTLOOK.EXE") }

// newOutlookRunning reports the WebView-based "new Outlook" (olk.exe), which has no COM interface.
func newOutlookRunning() bool {
	tl := filepath.Join(os.Getenv("SystemRoot"), "System32", "tasklist.exe")
	out, err := exec.Command(tl, "/FI", "IMAGENAME eq olk.exe", "/NH").Output()
	return err == nil && strings.Contains(strings.ToUpper(string(out)), "OLK.EXE")
}

var procSetConsoleTitleW = kernel32.NewProc("SetConsoleTitleW")

// setConsoleTitle puts the version in the console window title bar.
func setConsoleTitle(t string) {
	p, err := syscall.UTF16PtrFromString(t)
	if err != nil {
		return
	}
	procSetConsoleTitleW.Call(uintptr(unsafe.Pointer(p)))
}

var (
	procGetStdHandle       = kernel32.NewProc("GetStdHandle")
	procGetConsoleMode     = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode     = kernel32.NewProc("SetConsoleMode")
	procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
)

const stdOutputHandle = ^uintptr(10) // STD_OUTPUT_HANDLE = (DWORD)-11

// stdoutIsTerminal is true only when stdout is a real console (not redirected to a file or pipe).
func stdoutIsTerminal() bool {
	h, _, _ := procGetStdHandle.Call(stdOutputHandle)
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode)))
	return r != 0
}

// enableVT turns on ANSI colour processing and UTF-8 output. It returns false when the host
// console does not support virtual-terminal sequences, in which case the UI stays plain.
func enableVT() bool {
	h, _, _ := procGetStdHandle.Call(stdOutputHandle)
	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode))); r == 0 {
		return false
	}
	const enableProcessed, enableVTProc = 0x0001, 0x0004
	if r, _, _ := procSetConsoleMode.Call(h, uintptr(mode|enableProcessed|enableVTProc)); r == 0 {
		return false
	}
	procSetConsoleOutputCP.Call(65001)
	return true
}

// relaunchUnelevated starts this executable again in a new console window with a normal
// (basic-user) token, using the built-in runas /trustlevel option. The new process runs as the same
// account, without administrator rights, which is what Outlook automation needs.
func relaunchUnelevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	runas := filepath.Join(os.Getenv("SystemRoot"), "System32", "runas.exe")
	if _, err := os.Stat(runas); err != nil {
		return fmt.Errorf("runas.exe not found: %w", err)
	}
	parts := []string{syscall.EscapeArg(exe)}
	for _, a := range args {
		parts = append(parts, syscall.EscapeArg(a))
	}
	inner := strings.Join(parts, " ")
	cmd := exec.Command(runas)
	const createNewConsole = 0x00000010
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine:       syscall.EscapeArg(runas) + " /trustlevel:0x20000 " + syscall.EscapeArg(inner),
		CreationFlags: createNewConsole,
	}
	return cmd.Start()
}
