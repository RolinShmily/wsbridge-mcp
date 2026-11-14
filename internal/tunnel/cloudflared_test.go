package tunnel

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wsbridge/internal/config"
)

func TestCloudflaredTokenFileArgsAndRestart(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	const secretToken = "super-secret-cf-token-value"
	if err := os.WriteFile(tokenPath, []byte(secretToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var runs atomic.Int32
	var gotArgs []string
	var gotEnv []string
	runner := NewCloudflaredRunner(CloudflaredOptions{
		Binary:    "cloudflared",
		TokenFile: tokenPath,
		Listen:    "127.0.0.1:8787",
		Logger:    logger,
		LookPath:  func(bin string) (string, error) { return "/usr/bin/" + bin, nil },
		WaitReady: func(context.Context, string) error { return nil },
		Backoff:   func(int) time.Duration { return time.Millisecond },
		RunOnce: func(_ context.Context, _ string, args, env []string, logLine func(string)) error {
			gotArgs = args
			gotEnv = env
			logLine("INF Registered tunnel connection")
			if runs.Add(1) == 1 {
				return errors.New("exit status 1")
			}
			cancel()
			return nil
		},
	})

	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if runs.Load() != 2 {
		t.Fatalf("runs = %d, want 2 (1 crash + 1 restart)", runs.Load())
	}
	wantArgs := []string{"tunnel", "--no-autoupdate", "run", "--token-file", tokenPath}
	if strings.Join(gotArgs, "|") != strings.Join(wantArgs, "|") {
		t.Fatalf("args = %v, want %v", gotArgs, wantArgs)
	}
	if len(gotEnv) != 0 {
		t.Fatalf("expected no extra env for token_file mode, got %v", gotEnv)
	}
	if strings.Contains(logBuf.String(), secretToken) {
		t.Fatalf("tunnel token leaked in logs: %s", logBuf.String())
	}
}

func TestCloudflaredTokenEnvAndNoLeak(t *testing.T) {
	const envName = "WSBRIDGE_TEST_CF_TOKEN"
	const secretToken = "env-secret-cf-token-value"
	t.Setenv(envName, secretToken)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var gotArgs []string
	var gotEnv []string
	runner := NewCloudflaredRunner(CloudflaredOptions{
		Binary:    "cloudflared",
		TokenEnv:  envName,
		Listen:    "127.0.0.1:8787",
		Logger:    logger,
		LookPath:  func(bin string) (string, error) { return "/usr/bin/" + bin, nil },
		WaitReady: func(context.Context, string) error { return nil },
		RunOnce: func(_ context.Context, _ string, args, env []string, _ func(string)) error {
			gotArgs = args
			gotEnv = env
			cancel()
			return nil
		},
	})

	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	wantArgs := []string{"tunnel", "--no-autoupdate", "run"}
	if strings.Join(gotArgs, "|") != strings.Join(wantArgs, "|") {
		t.Fatalf("args = %v, want %v", gotArgs, wantArgs)
	}
	if len(gotEnv) != 1 || gotEnv[0] != "TUNNEL_TOKEN="+secretToken {
		t.Fatalf("extraEnv = %v, want [TUNNEL_TOKEN=<redacted>]", gotEnv)
	}
	if strings.Contains(logBuf.String(), secretToken) {
		t.Fatalf("tunnel token leaked in logs: %s", logBuf.String())
	}
}

func TestCloudflaredMissingBinaryOrEmptyTokenFailsFast(t *testing.T) {
	rMissingBin := NewCloudflaredRunner(CloudflaredOptions{
		Binary:   "cloudflared",
		TokenEnv: "WSBRIDGE_TEST_CF_TOKEN",
		LookPath: func(string) (string, error) { return "", errors.New("not found") },
	})
	if err := rMissingBin.Run(context.Background()); err == nil {
		t.Fatal("expected error when binary is missing")
	}

	emptyFile := filepath.Join(t.TempDir(), "empty-token")
	if err := os.WriteFile(emptyFile, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rEmptyToken := NewCloudflaredRunner(CloudflaredOptions{
		Binary:    "cloudflared",
		TokenFile: emptyFile,
		LookPath:  func(bin string) (string, error) { return "/usr/bin/" + bin, nil },
	})
	if err := rEmptyToken.Run(context.Background()); err == nil {
		t.Fatal("expected error when token_file is empty")
	}
}

func TestCheckManagedTunnelDoctor(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Tunnel: config.Tunnel{
			Provider:  "cloudflared",
			Binary:    "cloudflared",
			TokenFile: tokenPath,
		},
	}
	checks := checkManagedTunnelWith(cfg, func(string) (string, error) { return "/usr/bin/cloudflared", nil })
	if Failed(checks) {
		t.Fatalf("unexpected FAIL in checks: %+v", checks)
	}
	if len(checks) != 2 {
		t.Fatalf("checks len = %d, want 2", len(checks))
	}

	checksFail := checkManagedTunnelWith(cfg, func(string) (string, error) { return "", errors.New("missing") })
	if !Failed(checksFail) {
		t.Fatalf("expected FAIL when binary missing: %+v", checksFail)
	}
}
