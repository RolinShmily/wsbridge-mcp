package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"wsbridge/internal/config"
)

// CloudflaredOptions configures a managed cloudflared tunnel subprocess.
type CloudflaredOptions struct {
	Binary    string
	TokenFile string
	TokenEnv  string
	Listen    string
	Logger    *slog.Logger

	LookPath  func(string) (string, error)
	WaitReady func(context.Context, string) error
	RunOnce   func(ctx context.Context, binary string, args, extraEnv []string, logLine func(string)) error
	Backoff   func(attempt int) time.Duration
}

// CloudflaredRunner supervises a cloudflared tunnel subprocess.
type CloudflaredRunner struct {
	opts CloudflaredOptions
}

// NewCloudflaredRunner constructs a supervisor for a managed cloudflared tunnel.
func NewCloudflaredRunner(opts CloudflaredOptions) *CloudflaredRunner {
	if opts.Binary == "" {
		opts.Binary = "cloudflared"
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.LookPath == nil {
		opts.LookPath = exec.LookPath
	}
	if opts.WaitReady == nil {
		opts.WaitReady = waitTCPReady
	}
	if opts.RunOnce == nil {
		opts.RunOnce = runCloudflaredOnce
	}
	if opts.Backoff == nil {
		opts.Backoff = defaultBackoff
	}
	return &CloudflaredRunner{opts: opts}
}

// Run validates the binary and token source, waits for the local HTTP server
// to listen, and then supervises cloudflared until ctx is cancelled.
func (r *CloudflaredRunner) Run(ctx context.Context) error {
	binPath, err := r.opts.LookPath(r.opts.Binary)
	if err != nil {
		return fmt.Errorf("tunnel: locate %q: %w", r.opts.Binary, err)
	}

	args, extraEnv, err := r.buildInvocation()
	if err != nil {
		return err
	}

	if r.opts.Listen != "" {
		if err := r.opts.WaitReady(ctx, r.opts.Listen); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("tunnel: wait for local server %s: %w", r.opts.Listen, err)
		}
	}

	attempt := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		r.opts.Logger.Info("starting managed cloudflared tunnel", "binary", binPath)
		started := time.Now()
		err := r.opts.RunOnce(ctx, binPath, args, extraEnv, func(line string) {
			r.opts.Logger.Debug("cloudflared", "output", line)
		})
		if ctx.Err() != nil {
			r.opts.Logger.Info("managed cloudflared tunnel stopped")
			return nil
		}
		if time.Since(started) > 30*time.Second {
			attempt = 0
		}
		delay := r.opts.Backoff(attempt)
		attempt++
		r.opts.Logger.Warn("managed cloudflared tunnel exited unexpectedly; restarting",
			"error", err, "retry_in", delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func (r *CloudflaredRunner) buildInvocation() ([]string, []string, error) {
	args := []string{"tunnel", "--no-autoupdate", "run"}
	if r.opts.TokenFile != "" {
		raw, err := os.ReadFile(r.opts.TokenFile)
		if err != nil {
			return nil, nil, fmt.Errorf("tunnel: read token_file %q: %w", r.opts.TokenFile, err)
		}
		if strings.TrimSpace(string(raw)) == "" {
			return nil, nil, fmt.Errorf("tunnel: token_file %q is empty", r.opts.TokenFile)
		}
		return append(args, "--token-file", r.opts.TokenFile), nil, nil
	}
	if r.opts.TokenEnv != "" {
		tok := strings.TrimSpace(os.Getenv(r.opts.TokenEnv))
		if tok == "" {
			return nil, nil, fmt.Errorf("tunnel: environment variable %q is empty or unset", r.opts.TokenEnv)
		}
		return args, []string{"TUNNEL_TOKEN=" + tok}, nil
	}
	return nil, nil, fmt.Errorf("tunnel: token_file or token_env is required")
}

func defaultBackoff(attempt int) time.Duration {
	d := time.Second << min(attempt, 5)
	if d > 30*time.Second {
		return 30 * time.Second
	}
	return d
}

func waitTCPReady(ctx context.Context, addr string) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func runCloudflaredOnce(ctx context.Context, binary string, args, extraEnv []string, logLine func(string)) error {
	cmd := exec.CommandContext(ctx, binary, args...)
	configureCloudflaredCommand(cmd)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var wg sync.WaitGroup
	scan := func(rc io.ReadCloser) {
		defer wg.Done()
		sc := bufio.NewScanner(rc)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				logLine(line)
			}
		}
	}
	wg.Add(2)
	go scan(stdout)
	go scan(stderr)
	wg.Wait()
	return cmd.Wait()
}

func checkManagedTunnelWith(cfg *config.Config, lookPath func(string) (string, error)) []Check {
	if cfg == nil || cfg.Tunnel.Provider != "cloudflared" {
		return nil
	}
	var checks []Check
	bin := cfg.Tunnel.Binary
	if bin == "" {
		bin = "cloudflared"
	}
	if path, err := lookPath(bin); err == nil {
		checks = append(checks, Check{
			Name:   "managed tunnel binary",
			Level:  Pass,
			Detail: fmt.Sprintf("cloudflared found at %s", path),
		})
	} else {
		checks = append(checks, Check{
			Name:   "managed tunnel binary",
			Level:  Fail,
			Detail: fmt.Sprintf("%q not found in PATH: %v", bin, err),
		})
	}

	switch {
	case cfg.Tunnel.TokenFile != "":
		info, err := os.Stat(cfg.Tunnel.TokenFile)
		if err != nil {
			checks = append(checks, Check{
				Name:   "managed tunnel token",
				Level:  Fail,
				Detail: fmt.Sprintf("token_file %s is not readable: %v", cfg.Tunnel.TokenFile, err),
			})
		} else if raw, err := os.ReadFile(cfg.Tunnel.TokenFile); err != nil || strings.TrimSpace(string(raw)) == "" {
			checks = append(checks, Check{
				Name:   "managed tunnel token",
				Level:  Fail,
				Detail: fmt.Sprintf("token_file %s is empty or unreadable", cfg.Tunnel.TokenFile),
			})
		} else if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			checks = append(checks, Check{
				Name:   "managed tunnel token",
				Level:  Warn,
				Detail: fmt.Sprintf("token_file %s has permissions %04o; recommend 0600", cfg.Tunnel.TokenFile, info.Mode().Perm()),
			})
		} else {
			checks = append(checks, Check{
				Name:   "managed tunnel token",
				Level:  Pass,
				Detail: fmt.Sprintf("token_file %s is readable and non-empty", cfg.Tunnel.TokenFile),
			})
		}
	case cfg.Tunnel.TokenEnv != "":
		if strings.TrimSpace(os.Getenv(cfg.Tunnel.TokenEnv)) == "" {
			checks = append(checks, Check{
				Name:   "managed tunnel token",
				Level:  Fail,
				Detail: fmt.Sprintf("environment variable %s is empty or unset", cfg.Tunnel.TokenEnv),
			})
		} else {
			checks = append(checks, Check{
				Name:   "managed tunnel token",
				Level:  Pass,
				Detail: fmt.Sprintf("environment variable %s is set", cfg.Tunnel.TokenEnv),
			})
		}
	}
	return checks
}
