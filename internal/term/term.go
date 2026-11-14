// Package term reads secrets from a terminal without golang.org/x/term,
// which is outside the project's dependency whitelist.
package term

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ReadPassword reads one line from f. When f is a terminal, echo is disabled
// for the duration of the read; otherwise input is read as-is from the pipe.
func ReadPassword(f *os.File) (string, error) {
	if !IsTerminal(f) {
		return readLine(f)
	}
	restore, err := disableEcho(f)
	if err != nil {
		return "", err
	}
	defer restore()
	line, err := readLine(f)
	fmt.Fprintln(os.Stderr)
	return line, err
}

func readLine(f *os.File) (string, error) {
	var buf []byte
	one := make([]byte, 1)
	for {
		n, err := f.Read(one)
		if n > 0 {
			switch one[0] {
			case '\n':
				return string(buf), nil
			case '\r':
			default:
				buf = append(buf, one[0])
				if len(buf) > 4096 {
					return "", errors.New("term: input line is too long")
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(buf) == 0 {
					return "", io.EOF
				}
				return string(buf), nil
			}
			return "", err
		}
	}
}
