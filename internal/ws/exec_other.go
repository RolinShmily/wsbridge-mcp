//go:build !unix && !windows

package ws

import "os/exec"

// configureCheckCommand is a no-op on platforms without supported process
// groups; WaitDelay still bounds Wait when a grandchild holds the output pipe.
func configureCheckCommand(cmd *exec.Cmd) {}
