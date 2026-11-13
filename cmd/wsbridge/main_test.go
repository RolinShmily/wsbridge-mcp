package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"wsbridge/internal/config"
)

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestRunNoCommandShowsUsage(t *testing.T) {
	code, _, stderr := runCLI(t)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	for _, sub := range []string{"serve", "init", "passwd", "grants", "doctor", "service"} {
		if !strings.Contains(stderr, sub) {
			t.Errorf("usage missing %q: %s", sub, stderr)
		}
	}
}

func TestRunHelp(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h"} {
		code, stdout, _ := runCLI(t, arg)
		if code != 0 {
			t.Errorf("%s exit code = %d, want 0", arg, code)
		}
		if !strings.Contains(stdout, "Usage:") {
			t.Errorf("%s usage missing: %s", arg, stdout)
		}
	}
}

func TestRunUnknownCommand(t *testing.T) {
	code, _, stderr := runCLI(t, "nope")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestRunConfigFlagMissingValue(t *testing.T) {
	code, _, stderr := runCLI(t, "--config")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "--config") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestRunInitCreatesLoadableConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "wsbridge", "config.toml")

	code, stdout, stderr := runCLI(t, "--config", cfgPath, "init")
	if code != 0 {
		t.Fatalf("init exit code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "Created") || !strings.Contains(stdout, "passwd") {
		t.Errorf("stdout = %q", stdout)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("generated config is not loadable: %v", err)
	}
	dataDir, err := cfg.ResolvedDataDir()
	if err != nil {
		t.Fatalf("ResolvedDataDir: %v", err)
	}
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatalf("data dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("data dir %q is not a directory", dataDir)
	}
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("data dir mode = %o, want 700", got)
		}
	}
}

func TestRunInitRefusesExistingWithoutForce(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if code, _, stderr := runCLI(t, "--config", cfgPath, "init"); code != 0 {
		t.Fatalf("first init failed: %s", stderr)
	}
	code, _, stderr := runCLI(t, "--config", cfgPath, "init")
	if code != 1 {
		t.Errorf("second init exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "force") {
		t.Errorf("stderr = %q", stderr)
	}
	if code, _, stderr := runCLI(t, "--config", cfgPath, "init", "--force"); code != 0 {
		t.Errorf("forced init exit code = %d, stderr = %s", code, stderr)
	}
}

func TestRunConfigFlagAfterSubcommand(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	code, _, stderr := runCLI(t, "init", "--config", cfgPath)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr)
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("config not created: %v", err)
	}
}

func TestRunServeRejectsMissingConfig(t *testing.T) {
	code, _, stderr := runCLI(t, "--config", filepath.Join(t.TempDir(), "missing.toml"), "serve")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "config") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestRunServeRejectsBadFlag(t *testing.T) {
	code, _, _ := runCLI(t, "serve", "--bogus")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRunSkeletonCommandsReportNotImplemented(t *testing.T) {
	tests := [][]string{
		{"passwd"},
		{"grants", "list"},
		{"grants", "prune"},
		{"grants", "revoke", "wsb_grt_x"},
		{"doctor"},
		{"service", "status"},
	}
	for _, args := range tests {
		code, _, stderr := runCLI(t, args...)
		if code != 1 {
			t.Errorf("%v exit code = %d, want 1", args, code)
		}
		if !strings.Contains(stderr, "not implemented") {
			t.Errorf("%v stderr = %q", args, stderr)
		}
	}
}

func TestRunGrantsUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"grants"},
		{"grants", "bogus"},
		{"grants", "revoke"},
		{"service"},
		{"service", "bogus"},
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v exit code = %d, want 2", args, code)
		}
	}
}

func TestIsSystemAccount(t *testing.T) {
	yes := []string{"SYSTEM", "system", `NT AUTHORITY\SYSTEM`, `nt authority\system`, `COMPUTER\system`}
	for _, name := range yes {
		if !isSystemAccount(name) {
			t.Errorf("isSystemAccount(%q) = false, want true", name)
		}
	}
	no := []string{"", "alice", `NT AUTHORITY\NETWORK SERVICE`, "SYSTEMATIC", "root"}
	for _, name := range no {
		if isSystemAccount(name) {
			t.Errorf("isSystemAccount(%q) = true, want false", name)
		}
	}
}
