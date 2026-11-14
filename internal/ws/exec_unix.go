//go:build unix

package ws

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// configureCheckCommand puts the check in its own process group and makes
// context cancellation kill the whole group. The default CommandContext
// behavior only kills the direct child, which lets grandchildren survive and
// keep the output pipe open past the timeout.
func configureCheckCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}
