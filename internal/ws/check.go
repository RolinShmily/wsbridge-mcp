package ws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

var builtinChecks = map[string][]string{
	// Git
	"git_status": {"git", "status", "--short", "--branch"},
	"git_diff":   {"git", "diff"},
	"git_log":    {"git", "log", "-n", "20", "--oneline"},
	// Go
	"go_vet":   {"go", "vet", "./..."},
	"go_test":  {"go", "test", "./..."},
	"go_build": {"go", "build", "./..."},
	// Node / JS / TS
	"npm_lint":  {"npm", "run", "lint"},
	"npm_test":  {"npm", "test"},
	"npm_build": {"npm", "run", "build"},
	// Python (pytest, ruff, mypy, uv, pip)
	"pytest":        {"pytest"},
	"ruff_check":    {"ruff", "check", "."},
	"mypy":          {"mypy", "."},
	"uv_pytest":     {"uv", "run", "pytest"},
	"uv_ruff":       {"uv", "run", "ruff", "check", "."},
	"uv_mypy":       {"uv", "run", "mypy", "."},
	"uv_lock_check": {"uv", "lock", "--check"},
	"uv_pip_list":   {"uv", "pip", "list"},
	"uv_pip_check":  {"uv", "pip", "check"},
	"pip_list":      {"pip", "list"},
	"pip_check":     {"pip", "check"},
	// Rust
	"cargo_check": {"cargo", "check"},
	"cargo_test":  {"cargo", "test"},
}

// KnownCheck reports whether name is a built-in run_check identifier.
func KnownCheck(name string) bool {
	_, ok := builtinChecks[name]
	return ok
}

// BuiltinCheckNames returns all built-in check identifiers in sorted order.
func BuiltinCheckNames() []string {
	names := make([]string, 0, len(builtinChecks))
	for name := range builtinChecks {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

var checkEnvAllow = map[string]bool{
	"PATH": true, "HOME": true, "USERPROFILE": true,
	"TMPDIR": true, "TEMP": true, "TMP": true,
	"GOPATH": true, "GOROOT": true, "GOMODCACHE": true,
	"APPDATA": true, "LOCALAPPDATA": true,
	"SYSTEMROOT": true, "WINDIR": true, "COMSPEC": true, "PATHEXT": true,
	"VIRTUAL_ENV": true, "UV_CACHE_DIR": true, "UV_PYTHON_INSTALL_DIR": true,
	"PIP_CACHE_DIR": true, "PYTHONUTF8": true,
	"CARGO_HOME": true, "RUSTUP_HOME": true,
	"XDG_CACHE_HOME": true, "XDG_DATA_HOME": true,
	"LANG": true, "LC_ALL": true, "NODE_ENV": true,
}

// RunCheck executes a built-in check inside the workspace. When the workspace
// configured an explicit check whitelist, only those identifiers are permitted;
// otherwise every built-in check is enabled by default.
// A non-zero exit status is reported via exitCode with a nil error.
func (w *Workspace) RunCheck(ctx context.Context, checkName string) (string, int, error) {
	argv, ok := builtinChecks[checkName]
	if !ok || len(argv) == 0 {
		return "", 0, fmt.Errorf("%w: %q", ErrUnknownCheck, checkName)
	}
	if len(w.checks) > 0 {
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
