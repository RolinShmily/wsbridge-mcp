//go:build windows

package term

import (
	"fmt"
	"os"
	"syscall"
)

const enableEchoInput = 0x0004

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

// IsTerminal reports whether f is an interactive console.
func IsTerminal(f *os.File) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode) == nil
}

// disableEcho turns off ENABLE_ECHO_INPUT and returns a restore function.
func disableEcho(f *os.File) (func(), error) {
	handle := syscall.Handle(f.Fd())
	var mode uint32
	if err := syscall.GetConsoleMode(handle, &mode); err != nil {
		return nil, fmt.Errorf("term: read console mode: %w", err)
	}
	if err := setConsoleMode(handle, mode&^enableEchoInput); err != nil {
		return nil, err
	}
	return func() { _ = setConsoleMode(handle, mode) }, nil
}

func setConsoleMode(handle syscall.Handle, mode uint32) error {
	ok, _, err := procSetConsoleMode.Call(uintptr(handle), uintptr(mode))
	if ok == 0 {
		return fmt.Errorf("term: set console mode: %w", err)
	}
	return nil
}
