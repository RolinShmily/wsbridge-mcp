//go:build linux || darwin

package term

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// IsTerminal reports whether f is an interactive terminal.
func IsTerminal(f *os.File) bool {
	var state syscall.Termios
	return ioctlTermios(int(f.Fd()), ioctlGetTermios, &state) == nil
}

// disableEcho turns off local echo and returns a restore function.
func disableEcho(f *os.File) (func(), error) {
	fd := int(f.Fd())
	var old syscall.Termios
	if err := ioctlTermios(fd, ioctlGetTermios, &old); err != nil {
		return nil, fmt.Errorf("term: read terminal attributes: %w", err)
	}
	next := old
	next.Lflag &^= syscall.ECHO
	if err := ioctlTermios(fd, ioctlSetTermios, &next); err != nil {
		return nil, fmt.Errorf("term: disable terminal echo: %w", err)
	}
	return func() { _ = ioctlTermios(fd, ioctlSetTermios, &old) }, nil
}

func ioctlTermios(fd int, req uintptr, state *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(state)))
	if errno != 0 {
		return errno
	}
	return nil
}
