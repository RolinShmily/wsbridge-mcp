//go:build !linux

package tunnel

import "os/exec"

func configureCloudflaredCommand(*exec.Cmd) {}
