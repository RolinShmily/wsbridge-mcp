//go:build !linux && !darwin && !windows

package term

import (
	"fmt"
	"os"
)

// IsTerminal is unsupported on this platform.
func IsTerminal(*os.File) bool { return false }

func disableEcho(*os.File) (func(), error) {
	return nil, fmt.Errorf("term: terminal echo control is unsupported on this platform")
}
