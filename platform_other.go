//go:build !windows

package main

import (
	"errors"
	"os"
)

// Stubs so the platform-independent logic compiles and can be unit-tested off Windows.
// The real tool only does useful work on Windows.

func isAdmin() bool { return false }
func relaunchElevated(args []string) error {
	return errors.New("elevation is only supported on Windows")
}
func pauseIfOwnConsole()      {}
func outlookRunning() bool    { return true }
func newOutlookRunning() bool { return false }

func setConsoleTitle(string) {}

func stdoutIsTerminal() bool {
	st, err := os.Stdout.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
func enableVT() bool { return true }

func relaunchUnelevated(args []string) error {
	return errors.New("relaunching without elevation is only supported on Windows")
}
