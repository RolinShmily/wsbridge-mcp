package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"wsbridge/internal/config"
	"wsbridge/internal/httpx"
	"wsbridge/internal/oauth"
	"wsbridge/internal/service"
	"wsbridge/internal/ws"
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
	for _, sub := range []string{"serve", "use", "init", "passwd", "grants", "doctor", "service"} {
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

type fakeServiceManager struct {
	calls      []string
	configPath string
	status     service.Status
	err        error
}

func (f *fakeServiceManager) Install() error   { f.calls = append(f.calls, "install"); return f.err }
func (f *fakeServiceManager) Uninstall() error { f.calls = append(f.calls, "uninstall"); return f.err }
func (f *fakeServiceManager) Start() error     { f.calls = append(f.calls, "start"); return f.err }
func (f *fakeServiceManager) Stop() error      { f.calls = append(f.calls, "stop"); return f.err }
func (f *fakeServiceManager) Status() (service.Status, error) {
	return f.status, f.err
}

func runServiceFake(t *testing.T, cfgPath string, fake *fakeServiceManager, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runServiceWith(func(path string) (service.Manager, error) {
		fake.configPath = path
		return fake, nil
	}, cfgPath, args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRunServiceManagementActions(t *testing.T) {
	cfgPath := writeTestConfig(t, t.TempDir(), t.TempDir())
	for _, action := range []string{"install", "uninstall", "start", "stop"} {
		fake := &fakeServiceManager{}
		code, stdout, stderr := runServiceFake(t, cfgPath, fake, action)
		if code != 0 {
			t.Errorf("%s exit code = %d, want 0 (stderr %q)", action, code, stderr)
		}
		if len(fake.calls) != 1 || fake.calls[0] != action {
			t.Errorf("%s calls = %v, want [%s]", action, fake.calls, action)
		}
		if fake.configPath != cfgPath {
			t.Errorf("%s config path = %q, want %q", action, fake.configPath, cfgPath)
		}
		if !strings.Contains(stdout, "wsbridge") {
			t.Errorf("%s stdout = %q", action, stdout)
		}
	}
}

func TestRunServiceStatus(t *testing.T) {
	cfgPath := writeTestConfig(t, t.TempDir(), t.TempDir())
	fake := &fakeServiceManager{status: service.StatusRunning}
	code, stdout, _ := runServiceFake(t, cfgPath, fake, "status")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "running") {
		t.Errorf("stdout = %q", stdout)
	}

	fake = &fakeServiceManager{status: service.StatusUnknown}
	if code, _, _ := runServiceFake(t, cfgPath, fake, "status"); code != 1 {
		t.Errorf("unknown status exit code = %d, want 1", code)
	}

	fake = &fakeServiceManager{err: service.ErrNotInstalled}
	code, _, stderr := runServiceFake(t, cfgPath, fake, "status")
	if code != 1 {
		t.Errorf("not-installed exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "not installed") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestRunServiceInstallValidatesConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.toml")
	fake := &fakeServiceManager{}
	code, _, stderr := runServiceFake(t, missing, fake, "install")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if len(fake.calls) != 0 {
		t.Errorf("install was called for an invalid config: %v", fake.calls)
	}
	if !strings.Contains(stderr, "config") && !strings.Contains(stderr, "no such file") {
		t.Errorf("stderr = %q", stderr)
	}
}

func hostedTestServer(t *testing.T) (*httpx.Server, net.Listener, *slog.Logger) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httpx.New(httpx.Options{
		Listener: ln,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "ok")
		}),
		Logger: logger,
	})
	return srv, ln, logger
}

func TestRunHostedServeStartsAndStops(t *testing.T) {
	srv, ln, logger := hostedTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	run := func(program *service.FuncProgram) error {
		if err := program.Start(nil); err != nil {
			return err
		}
		requestCtx, requestCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer requestCancel()
		req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("server did not answer after Start: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if string(body) != "ok" {
			t.Fatalf("body = %q, want ok", body)
		}
		return program.Stop(nil)
	}
	if code := runHostedServeWith(ctx, cancel, srv, logger, run); code != exitOK {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestRunHostedServeReportsControlError(t *testing.T) {
	srv, _, logger := hostedTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	run := func(*service.FuncProgram) error { return errors.New("service control failed") }
	if code := runHostedServeWith(ctx, cancel, srv, logger, run); code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
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

func TestWorkspaceConfigs(t *testing.T) {
	cfg := &config.Config{Workspaces: []config.Workspace{
		{Name: "app", Path: "/tmp/app", MaxPerm: config.PermCheck, Checks: []string{"git_status"}},
		{Name: "docs", Path: "/tmp/docs", MaxPerm: config.PermRead},
	}}
	got, err := workspaceConfigs(cfg)
	if err != nil {
		t.Fatalf("workspaceConfigs: %v", err)
	}
	if len(got) != 2 || got[0].Name != "app" || got[1].Name != "docs" {
		t.Fatalf("workspaces = %+v", got)
	}
	if got[0].MaxPerm.String() != "check" || got[1].MaxPerm.String() != "read" {
		t.Errorf("permissions = %v, %v", got[0].MaxPerm, got[1].MaxPerm)
	}
	cfg.Workspaces[0].MaxPerm = config.Permission("admin")
	if _, err := workspaceConfigs(cfg); err == nil {
		t.Error("invalid permission accepted")
	}
}

func TestRunServeWithoutDevNoAuthRefuses(t *testing.T) {
	dir := t.TempDir()
	wsDir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	content := `
public_url = "https://bridge.example.com"
listen = "127.0.0.1:8787"
data_dir = "` + escapeTOMLPath(dir) + `"

[[workspace]]
name = "app"
path = "` + escapeTOMLPath(wsDir) + `"
max_perm = "read"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, "--config", cfgPath, "serve")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "passwd") {
		t.Errorf("stderr = %q", stderr)
	}
}

func escapeTOMLPath(path string) string {
	return strings.ReplaceAll(path, `\`, `\\`)
}

func writeTestConfig(t *testing.T, dir, wsDir string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "config.toml")
	content := `
public_url = "https://bridge.example.com"
listen = "127.0.0.1:8787"
data_dir = "` + escapeTOMLPath(dir) + `"

[[workspace]]
name = "app"
path = "` + escapeTOMLPath(wsDir) + `"
max_perm = "check"
checks = ["git_status"]
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestRunPasswdStoresArgon2Hash(t *testing.T) {
	dir := t.TempDir()
	wsDir := t.TempDir()
	cfgPath := writeTestConfig(t, dir, wsDir)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	const pass = "correct horse battery"
	if _, err := io.WriteString(w, pass+"\n"+pass+"\n"); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	var stdout, stderr bytes.Buffer
	code := runPasswd(cfgPath, nil, r, &stdout, &stderr)
	_ = r.Close()
	if code != 0 {
		t.Fatalf("passwd exit code = %d, stderr = %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), pass) || strings.Contains(stdout.String(), pass) {
		t.Fatal("passphrase was echoed to output")
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	dataDir, err := cfg.ResolvedDataDir()
	if err != nil {
		t.Fatal(err)
	}
	store, err := oauth.OpenStore(filepath.Join(dataDir, "wsbridge.db"), oauth.StoreOptions{Issuer: cfg.PublicURL})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	hash, err := store.AdminHash()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("stored hash = %q", hash)
	}
	ok, err := oauth.VerifyAdminPassphrase(hash, pass)
	if err != nil || !ok {
		t.Fatalf("VerifyAdminPassphrase = %v, %v", ok, err)
	}
}

func TestRunPasswdValidation(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"short", "short\nshort\n", "at least 10"},
		{"mismatch", "long-enough-pass\nlong-enough-other\n", "do not match"},
		{"eof", "", "read passphrase"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := writeTestConfig(t, dir, t.TempDir())
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(w, tc.input)
			_ = w.Close()
			var stdout, stderr bytes.Buffer
			code := runPasswd(cfgPath, nil, r, &stdout, &stderr)
			_ = r.Close()
			if code != 1 {
				t.Fatalf("exit code = %d, want 1 (stderr %s)", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr.String(), tc.want)
			}
		})
	}
}

func TestRunGrantsListRevokePrune(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeTestConfig(t, dir, t.TempDir())
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	dataDir, err := cfg.ResolvedDataDir()
	if err != nil {
		t.Fatal(err)
	}
	grantID := "wsb_grt_testgrant"
	store, err := oauth.OpenStore(filepath.Join(dataDir, "wsbridge.db"), oauth.StoreOptions{Issuer: cfg.PublicURL})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.CreateGrant(&oauth.GrantRecord{
		GrantID:    grantID,
		ClientID:   "wsb_cli_test",
		ClientName: "Claude",
		Scopes:     []string{"mcp:tools"},
		Workspaces: map[string]ws.Permission{"app": ws.PermRead},
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.IssueTokens(grantID, "wsb_cli_test", cfg.PublicURL+"/mcp"); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()

	snapshotDir := filepath.Join(dataDir, "snapshots", grantID, "20260101-000000.000", "app")
	if err := os.MkdirAll(snapshotDir, 0o700); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runCLI(t, "--config", cfgPath, "grants", "list")
	if code != 0 {
		t.Fatalf("list exit code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{grantID, "Claude", "app:read", "active"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("list output missing %q:\n%s", want, stdout)
		}
	}

	code, stdout, stderr = runCLI(t, "--config", cfgPath, "grants", "revoke", grantID)
	if code != 0 {
		t.Fatalf("revoke exit code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, grantID) {
		t.Errorf("revoke stdout = %q", stdout)
	}

	store, err = oauth.OpenStore(filepath.Join(dataDir, "wsbridge.db"), oauth.StoreOptions{Issuer: cfg.PublicURL})
	if err != nil {
		t.Fatal(err)
	}
	g, err := store.GetGrant(grantID)
	if err != nil {
		t.Fatal(err)
	}
	if !g.Revoked {
		t.Error("grant is not revoked")
	}
	_ = store.Close()

	code, stdout, stderr = runCLI(t, "--config", cfgPath, "grants", "prune")
	if code != 0 {
		t.Fatalf("prune exit code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "Pruned 1 grant(s)") {
		t.Errorf("prune stdout = %q", stdout)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "snapshots", grantID)); !os.IsNotExist(err) {
		t.Errorf("orphaned snapshot directory was not removed: %v", err)
	}

	if code, _, _ := runCLI(t, "--config", cfgPath, "grants", "revoke", "wsb_grt_missing"); code != 1 {
		t.Errorf("revoke missing grant exit code = %d, want 1", code)
	}
}

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return port
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

const cliE2EPassphrase = "cli-e2e-passphrase"

type cliBearerTransport struct {
	base  http.RoundTripper
	token string
}

func (t *cliBearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(clone)
}

func TestServeOAuthEndToEnd(t *testing.T) {
	dir := t.TempDir()
	wsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(wsDir, "a.txt"), []byte("hello from workspace\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	port := freeLoopbackPort(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	publicURL := "http://" + addr
	cfgPath := filepath.Join(dir, "config.toml")
	content := `
public_url = "` + publicURL + `"
listen = "` + addr + `"
data_dir = "` + escapeTOMLPath(dir) + `"

[[workspace]]
name = "app"
path = "` + escapeTOMLPath(wsDir) + `"
max_perm = "check"
checks = ["git_status"]
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	// Seed the administrator passphrase the same way "wsbridge passwd" would.
	store, err := oauth.OpenStore(filepath.Join(dir, "wsbridge.db"), oauth.StoreOptions{Issuer: publicURL})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := oauth.HashAdminPassphrase(cliE2EPassphrase, oauth.Argon2Params{
		Memory: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetAdminHash(hash); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stderr := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- runServeContext(ctx, cfgPath, []string{"--allow-http-public-url"}, io.Discard, stderr)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("serve did not start: %s", stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	base := publicURL

	// /mcp without a token must be a JSON 401, never a redirect.
	resp, err := noRedirect.Post(base+"/mcp", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/mcp status = %d, want 401: %s", resp.StatusCode, raw)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("/mcp redirected to %q", loc)
	}

	// Dynamic registration with a loopback callback.
	redirectURI := "http://127.0.0.1:19999/callback"
	regBody := `{"client_name":"CLI E2E","redirect_uris":["` + redirectURI + `"]}`
	resp, err = noRedirect.Post(base+"/oauth/register", "application/json", strings.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d: %s", resp.StatusCode, raw)
	}
	var registration struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(raw, &registration); err != nil {
		t.Fatal(err)
	}

	// PKCE authorization + consent.
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(random)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	q := url.Values{
		"response_type": {"code"}, "client_id": {registration.ClientID},
		"redirect_uri": {redirectURI}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "state": {"cli-state"},
		"scope": {"mcp:tools offline_access"}, "resource": {base + "/mcp"},
	}
	resp, err = noRedirect.Get(base + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "CLI E2E") {
		t.Fatalf("authorize GET status = %d", resp.StatusCode)
	}
	authReq := regexp.MustCompile(`name="auth_req_id" value="([^"]+)"`).FindSubmatch(raw)
	csrf := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindSubmatch(raw)
	if authReq == nil || csrf == nil {
		t.Fatal("consent page missing hidden fields")
	}
	resp, err = noRedirect.PostForm(base+"/oauth/authorize", url.Values{
		"auth_req_id": {string(authReq[1])}, "csrf_token": {string(csrf[1])},
		"action": {"approve"}, "workspaces": {"app"}, "permission": {"check"},
		"ttl_hours": {"1"}, "passphrase": {cliE2EPassphrase},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize POST status = %d", resp.StatusCode)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := location.Query().Get("iss"); got != base {
		t.Errorf("iss = %q, want %q", got, base)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatal("authorization redirect has no code")
	}

	// Code exchange.
	resp, err = noRedirect.PostForm(base+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"client_id": {registration.ClientID}, "code_verifier": {verifier}, "resource": {base + "/mcp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || tokens.AccessToken == "" {
		t.Fatalf("token status = %d", resp.StatusCode)
	}

	// Authenticated MCP call through the real CLI-started server.
	client := mcp.NewClient(&mcp.Implementation{Name: "cli-e2e", Version: "1"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             base + "/mcp",
		HTTPClient:           &http.Client{Transport: &cliBearerTransport{base: http.DefaultTransport, token: tokens.AccessToken}},
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		cancel()
		t.Fatalf("MCP connect: %v (stderr: %s)", err, stderr.String())
	}
	list, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(list.Tools) != 7 {
		t.Errorf("tools = %d, want 7", len(list.Tools))
	}
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "read_file", Arguments: map[string]any{"path": "a.txt"},
	})
	if err != nil || res.IsError {
		t.Fatalf("read_file: %v %+v", err, res)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok || !strings.Contains(text.Text, "hello from workspace") {
		t.Fatalf("read_file content = %+v", res.Content)
	}
	for _, path := range []string{"../escape.txt", ".env"} {
		res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{
			Name: "read_file", Arguments: map[string]any{"path": path},
		})
		if err != nil {
			t.Fatalf("read_file(%q): %v", path, err)
		}
		if !res.IsError {
			t.Errorf("read_file(%q) was not blocked", path)
		}
	}
	_ = cs.Close()

	doctorCode, doctorOut, doctorErr := runCLI(t, "--config", cfgPath, "doctor", "--allow-http-public-url", "--timeout", "2s")
	if doctorCode != 0 {
		t.Fatalf("doctor exit code = %d\n%s\n%s", doctorCode, doctorOut, doctorErr)
	}
	for _, want := range []string{"[PASS] public PRM", "[PASS] public /mcp", "[PASS] public DCR"} {
		if !strings.Contains(doctorOut, want) {
			t.Errorf("doctor output missing %q:\n%s", want, doctorOut)
		}
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exit code = %d, stderr = %s", code, stderr.String())
		}
	case <-time.After(8 * time.Second):
		t.Fatal("serve did not shut down")
	}

	auditRaw, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{cliE2EPassphrase, tokens.AccessToken, tokens.RefreshToken, code, verifier} {
		if strings.Contains(string(auditRaw), secret) {
			t.Errorf("audit log contains secret %q", secret)
		}
	}
	for _, event := range []string{"dcr_register", "authorize_attempt", "token_issue", "tool_call", "sandbox_blocked"} {
		if !strings.Contains(string(auditRaw), `"event":"`+event+`"`) {
			t.Errorf("audit log missing event %q", event)
		}
	}
}

func TestRunInitInteractive(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "cfg", "config.toml")

	input := strings.Join([]string{
		"1",                       // tunnel: 1 = cloudflared
		"https://mcp.example.com", // public_url
		"127.0.0.1:8787",          // listen
		"y",                       // set passphrase now?
	}, "\n") + "\n"

	var stdout, stderr bytes.Buffer
	passCalls := 0
	code := runInitInteractive(cfgPath, strings.NewReader(input), &stdout, &stderr, func() (string, error) {
		passCalls++
		if passCalls == 1 {
			return "cf-token-secret", nil
		}
		return "correct horse battery staple", nil
	})
	if code != 0 {
		t.Fatalf("runInitInteractive exit = %d, stderr = %s\nstdout = %s", code, stderr.String(), stdout.String())
	}
	if passCalls != 3 {
		t.Fatalf("secret read calls = %d, want 3 (tunnel token + passphrase + confirm)", passCalls)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.PublicURL != "https://mcp.example.com" {
		t.Errorf("PublicURL = %q", cfg.PublicURL)
	}
	if cfg.Tunnel.Provider != "cloudflared" || cfg.Tunnel.TokenFile != filepath.Join(filepath.Dir(cfgPath), "cloudflared-token") {
		t.Errorf("Tunnel = %+v", cfg.Tunnel)
	}
	if len(cfg.Workspaces) != 0 {
		t.Errorf("Workspaces = %+v, want empty (dynamic CWD mode)", cfg.Workspaces)
	}
	if cfg.EffectiveMaxPerm() != config.PermCheck {
		t.Errorf("EffectiveMaxPerm = %q, want check", cfg.EffectiveMaxPerm())
	}
	if !strings.Contains(stdout.String(), "https://mcp.example.com/mcp") {
		t.Errorf("stdout missing MCP endpoint URL:\n%s", stdout.String())
	}

	dataDir, err := cfg.ResolvedDataDir()
	if err != nil {
		t.Fatal(err)
	}
	store, err := oauth.OpenStore(filepath.Join(dataDir, "wsbridge.db"), oauth.StoreOptions{Issuer: cfg.PublicURL})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	hash, err := store.AdminHash()
	if err != nil || hash == "" {
		t.Fatalf("expected admin hash to be saved, got hash=%q err=%v", hash, err)
	}
}

func TestRunInitInteractiveSavesPastedTunnelToken(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "cfg", "config.toml")

	input := strings.Join([]string{
		"1",
		"https://mcp.example.com",
		"127.0.0.1:8787",
		"n",
	}, "\n") + "\n"

	var stdout, stderr bytes.Buffer
	code := runInitInteractive(cfgPath, strings.NewReader(input), &stdout, &stderr, func() (string, error) {
		return "cloudflared.exe service install pasted-cf-token-123", nil
	})
	if code != 0 {
		t.Fatalf("runInitInteractive exit = %d, stderr = %s", code, stderr.String())
	}
	gotToken, err := os.ReadFile(filepath.Join(filepath.Dir(cfgPath), "cloudflared-token"))
	if err != nil {
		t.Fatalf("read saved token: %v", err)
	}
	if string(gotToken) != "pasted-cf-token-123" {
		t.Fatalf("saved token = %q, want %q", string(gotToken), "pasted-cf-token-123")
	}
	if strings.Contains(stdout.String(), "pasted-cf-token-123") {
		t.Fatal("tunnel token leaked to stdout")
	}
}

func TestServeDynamicWorkspaceAndLiveUseSwitch(t *testing.T) {
	dir := t.TempDir()
	projA := filepath.Join(t.TempDir(), "proj-a")
	projB := filepath.Join(t.TempDir(), "proj-b")
	if err := os.MkdirAll(projA, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(projB, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projA, "info.txt"), []byte("project A\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projB, "info.txt"), []byte("project B\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	port := freeLoopbackPort(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	publicURL := "http://" + addr
	cfgPath := filepath.Join(dir, "config.toml")
	// Notice: NO [[workspace]] blocks and NO max_perm in config.toml.
	content := `
public_url = "` + publicURL + `"
listen = "` + addr + `"
data_dir = "` + escapeTOMLPath(dir) + `"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	// Offline "wsbridge use" saves active workspace before serve starts.
	useCode, useOut, useErr := runCLI(t, "--config", cfgPath, "use", projA)
	if useCode != 0 {
		t.Fatalf("offline use exit = %d, stderr = %s", useCode, useErr)
	}
	if !strings.Contains(useOut, "proj-a") || !strings.Contains(useOut, "not running") {
		t.Fatalf("offline use stdout = %q", useOut)
	}

	store, err := oauth.OpenStore(filepath.Join(dir, "wsbridge.db"), oauth.StoreOptions{Issuer: publicURL})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := oauth.HashAdminPassphrase(cliE2EPassphrase, oauth.Argon2Params{
		Memory: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetAdminHash(hash); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stderr := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- runServeContext(ctx, cfgPath, []string{"--allow-http-public-url", projA}, io.Discard, stderr)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("serve did not start: %s", stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	redirectURI := "http://127.0.0.1:19999/callback"
	regResp, err := noRedirect.Post(publicURL+"/oauth/register", "application/json",
		strings.NewReader(`{"client_name":"Dynamic E2E","redirect_uris":["`+redirectURI+`"]}`))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(regResp.Body).Decode(&reg)
	regResp.Body.Close()

	random := make([]byte, 32)
	_, _ = rand.Read(random)
	verifier := base64.RawURLEncoding.EncodeToString(random)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	q := url.Values{
		"response_type": {"code"}, "client_id": {reg.ClientID},
		"redirect_uri": {redirectURI}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "state": {"dyn"},
		"scope": {"mcp:tools offline_access"}, "resource": {publicURL + "/mcp"},
	}
	getResp, err := noRedirect.Get(publicURL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	authReq := regexp.MustCompile(`name="auth_req_id" value="([^"]+)"`).FindSubmatch(raw)
	csrf := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindSubmatch(raw)

	// Simplified consent submit: NO "workspaces" param!
	postResp, err := noRedirect.PostForm(publicURL+"/oauth/authorize", url.Values{
		"auth_req_id": {string(authReq[1])}, "csrf_token": {string(csrf[1])},
		"action": {"approve"}, "permission": {"check"}, "ttl_hours": {"720"},
		"passphrase": {cliE2EPassphrase},
	})
	if err != nil {
		t.Fatal(err)
	}
	postResp.Body.Close()
	loc, _ := url.Parse(postResp.Header.Get("Location"))
	code := loc.Query().Get("code")

	tokResp, err := noRedirect.PostForm(publicURL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"client_id": {reg.ClientID}, "code_verifier": {verifier}, "resource": {publicURL + "/mcp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(tokResp.Body).Decode(&tokens)
	tokResp.Body.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "dyn-client", Version: "1"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             publicURL + "/mcp",
		HTTPClient:           &http.Client{Transport: &cliBearerTransport{base: http.DefaultTransport, token: tokens.AccessToken}},
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("MCP connect: %v", err)
	}
	defer cs.Close()

	// Verify initial active workspace is proj-a.
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "read_file", Arguments: map[string]any{"path": "info.txt"},
	})
	if err != nil || res.IsError {
		t.Fatalf("read proj-a: %v %+v", err, res)
	}
	if !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "project A") {
		t.Fatalf("proj-a content = %q", res.Content[0].(*mcp.TextContent).Text)
	}

	// Live hot-switch via "wsbridge use <projB>" while serve stays running!
	switchCode, switchOut, switchErr := runCLI(t, "--config", cfgPath, "use", projB)
	if switchCode != 0 {
		t.Fatalf("live use exit = %d, stderr = %s", switchCode, switchErr)
	}
	if !strings.Contains(switchOut, "Switched active workspace to proj-b") {
		t.Fatalf("live use stdout = %q", switchOut)
	}

	// "wsbridge use --show" reports live proj-b.
	showCode, showOut, showErr := runCLI(t, "--config", cfgPath, "use", "--show")
	if showCode != 0 || !strings.Contains(showOut, "proj-b") || !strings.Contains(showOut, "live") {
		t.Fatalf("use --show = (%d, %q, %q)", showCode, showOut, showErr)
	}

	// Same MCP session & OAuth token now seamlessly reads proj-b!
	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "list_workspaces", Arguments: map[string]any{},
	})
	if err != nil || res.IsError {
		t.Fatalf("list_workspaces after switch: %v %+v", err, res)
	}
	if text := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(text, "name: proj-b") || !strings.Contains(text, "uv_pytest") {
		t.Fatalf("list_workspaces after switch = %q", text)
	}

	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "read_file", Arguments: map[string]any{"path": "info.txt"},
	})
	if err != nil || res.IsError {
		t.Fatalf("read proj-b: %v %+v", err, res)
	}
	if !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "project B") {
		t.Fatalf("proj-b content = %q", res.Content[0].(*mcp.TextContent).Text)
	}

	// Stale explicit workspace name "proj-a" fails clearly instead of mis-editing proj-b.
	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "read_file", Arguments: map[string]any{"workspace": "proj-a", "path": "info.txt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "proj-b") {
		t.Fatalf("stale workspace call should error and mention proj-b: %+v", res)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exit code = %d, stderr = %s", code, stderr.String())
		}
	case <-time.After(8 * time.Second):
		t.Fatal("serve did not shut down")
	}
}
