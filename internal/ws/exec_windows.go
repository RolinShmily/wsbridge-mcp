//go:build windows

package ws

import "os/exec"

// configureCheckCommand leaves process-group handling to WaitDelay on Windows:
// os/exec can close the inherited output pipe after the deadline even when a
// grandchild still holds it. Killing a whole Windows process tree needs a Job
// Object, which is outside the standard library surface used here.
func configureCheckCommand(cmd *exec.Cmd) {}
