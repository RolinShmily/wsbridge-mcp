package ws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var builtinChecks = map[string][]string{
	"git_status": {"git", "status", "--short", "--branch"},
	"git_diff":   {"git", "diff"},
	"go_vet":     {"go", "vet", "./..."},
	"go_test":    {"go", "test", "./..."},
	"npm_lint":   {"npm", "run", "lint"},
	"npm_test":   {"npm", "test"},
}

var checkEnvAllow = map[string]bool{
	"PATH": true, "HOME": true, "USERPROFILE": true,
	"TMPDIR": true, "TEMP": true,
	"GOPATH": true, "GOROOT": true, "GOMODCACHE": true,
	"APPDATA": true, "LOCALAPPDATA": true,
}

// RunCheck executes a configured whitelist check inside the workspace.
// A non-zero exit status is reported via exitCode with a nil error.
func (w *Workspace) RunCheck(ctx context.Context, checkName string) (string, int, error) {
	allowed := false
	for _, check := range w.checks {
		if check == checkName {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", 0, fmt.Errorf("%w: %q", ErrCheckNotAllowed, checkName)
	}
	argv, ok := builtinChecks[checkName]
	if !ok || len(argv) == 0 {
		return "", 0, fmt.Errorf("%w: %q", ErrUnknownCheck, checkName)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...)
	cmd.Dir = w.hostPath
	cmd.Env = filteredCheckEnv()
	// Capture only the head of the output; CombinedOutput would buffer an
	// unbounded stream from a noisy or hostile check before truncation.
	capture := &cappedWriter{limit: MaxCheckOutput + 4}
	cmd.Stdout = capture
	cmd.Stderr = capture
	// If a grandchild inherits the output pipe and outlives the check, Wait
	// would otherwise block on the pipe copy even after the child exits.
	cmd.WaitDelay = 2 * time.Second
	configureCheckCommand(cmd)

	err := cmd.Run()
	text := truncateCheckOutput(capture.String())
	if runCtx.Err() != nil {
		return text, 0, fmt.Errorf("check %q timed out or was canceled: %w", checkName, runCtx.Err())
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return text, exitErr.ExitCode(), nil
		}
		if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil {
			return text, cmd.ProcessState.ExitCode(), nil
		}
		return text, 0, fmt.Errorf("run check %q: %w", checkName, err)
	}
	return text, 0, nil
}

// cappedWriter keeps at most limit bytes and silently discards the rest, so a
// check that prints gigabytes cannot exhaust memory. Write always reports the
// full length as written so the child is not blocked by a short write.
type cappedWriter struct {
	mu        sync.Mutex
	limit     int
	buf       bytes.Buffer
	truncated bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.truncated {
		remaining := c.limit - c.buf.Len()
		switch {
		case remaining <= 0:
			c.truncated = true
		case len(p) > remaining:
			_, _ = c.buf.Write(p[:remaining])
			c.truncated = true
		default:
			_, _ = c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *cappedWriter) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func filteredCheckEnv() []string {
	env := make([]string, 0, len(checkEnvAllow))
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if checkEnvAllow[strings.ToUpper(key)] {
			env = append(env, entry)
		}
	}
	return env
}
