package config_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"wsbridge/internal/config"
)

func writeConfigFile(t *testing.T, content string) (path string, dir string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path, dir
}

func TestLoadValidConfig(t *testing.T) {
	wsA := t.TempDir()
	wsB := t.TempDir()
	cfgPath, cfgDir := writeConfigFile(t, `
public_url = "https://bridge.example.com"
listen = "127.0.0.1:9999"
allow_redirect_hosts = ["example.org"]
deny_patterns = ["*.secret", "private/*"]
max_snapshots_per_grant = 5

[[workspace]]
name = "app"
path = "`+escapeTOML(wsA)+`"
max_perm = "write"
checks = ["git_status", "git_diff"]

[[workspace]]
name = "notes"
path = "`+escapeTOML(wsB)+`"
max_perm = "read"
checks = []
`)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PublicURL != "https://bridge.example.com" {
		t.Errorf("PublicURL = %q", cfg.PublicURL)
	}
	if cfg.Listen != "127.0.0.1:9999" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if cfg.MaxSnapshotsPerGrant != 5 {
		t.Errorf("MaxSnapshotsPerGrant = %d", cfg.MaxSnapshotsPerGrant)
	}
	if len(cfg.AllowRedirectHosts) != 1 || cfg.AllowRedirectHosts[0] != "example.org" {
		t.Errorf("AllowRedirectHosts = %v", cfg.AllowRedirectHosts)
	}
	if len(cfg.DenyPatterns) != 2 {
		t.Errorf("DenyPatterns = %v", cfg.DenyPatterns)
	}
	if len(cfg.Workspaces) != 2 {
		t.Fatalf("Workspaces len = %d", len(cfg.Workspaces))
	}
	if cfg.Workspaces[0].Name != "app" || cfg.Workspaces[0].MaxPerm != config.PermWrite {
		t.Errorf("Workspaces[0] = %+v", cfg.Workspaces[0])
	}
	if got, want := cfg.Workspaces[0].Checks, []string{"git_status", "git_diff"}; !equalStrings(got, want) {
		t.Errorf("Checks = %v, want %v", got, want)
	}

	dataDir, err := cfg.ResolvedDataDir()
	if err != nil {
		t.Fatalf("ResolvedDataDir: %v", err)
	}
	if dataDir != cfgDir {
		t.Errorf("ResolvedDataDir = %q, want %q", dataDir, cfgDir)
	}
	if cfg.ConfigPath() != cfgPath {
		t.Errorf("ConfigPath = %q, want %q", cfg.ConfigPath(), cfgPath)
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	cfgPath, cfgDir := writeConfigFile(t, `public_url = "https://bridge.example.com"`)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != config.DefaultListen {
		t.Errorf("Listen = %q, want %q", cfg.Listen, config.DefaultListen)
	}
	if cfg.MaxSnapshotsPerGrant != config.DefaultMaxSnapshotsPerGrant {
		t.Errorf("MaxSnapshotsPerGrant = %d", cfg.MaxSnapshotsPerGrant)
	}
	dataDir, err := cfg.ResolvedDataDir()
	if err != nil {
		t.Fatalf("ResolvedDataDir: %v", err)
	}
	if dataDir != cfgDir {
		t.Errorf("ResolvedDataDir = %q, want %q", dataDir, cfgDir)
	}
}

func TestLoadRejectsInvalidConfig(t *testing.T) {
	wsDir := t.TempDir()
	filePath := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		toml    string
		wantSub string
	}{
		{
			name:    "missing public_url",
			toml:    `listen = "127.0.0.1:8787"`,
			wantSub: "public_url",
		},
		{
			name:    "http public_url rejected",
			toml:    `public_url = "http://bridge.example.com"`,
			wantSub: "https",
		},
		{
			name:    "trailing slash",
			toml:    `public_url = "https://bridge.example.com/"`,
			wantSub: "public_url",
		},
		{
			name:    "path in public_url",
			toml:    `public_url = "https://bridge.example.com/base"`,
			wantSub: "public_url",
		},
		{
			name:    "query in public_url",
			toml:    `public_url = "https://bridge.example.com?x=1"`,
			wantSub: "public_url",
		},
		{
			name:    "empty host",
			toml:    `public_url = "https://"`,
			wantSub: "public_url",
		},
		{
			name:    "listen without port",
			toml:    `public_url = "https://bridge.example.com"` + "\n" + `listen = "127.0.0.1"`,
			wantSub: "listen",
		},
		{
			name:    "listen bad port",
			toml:    `public_url = "https://bridge.example.com"` + "\n" + `listen = "127.0.0.1:70000"`,
			wantSub: "listen",
		},
		{
			name:    "listen non numeric port",
			toml:    `public_url = "https://bridge.example.com"` + "\n" + `listen = "127.0.0.1:http"`,
			wantSub: "listen",
		},
		{
			name:    "relative data_dir",
			toml:    `public_url = "https://bridge.example.com"` + "\n" + `data_dir = "data"`,
			wantSub: "data_dir",
		},
		{
			name:    "negative snapshots",
			toml:    `public_url = "https://bridge.example.com"` + "\n" + `max_snapshots_per_grant = -1`,
			wantSub: "max_snapshots_per_grant",
		},
		{
			name:    "empty workspace name",
			toml:    wsToml("", wsDir, "read", "[]"),
			wantSub: "name",
		},
		{
			name:    "invalid workspace name",
			toml:    wsToml("my app", wsDir, "read", "[]"),
			wantSub: "name",
		},
		{
			name:    "dotdot workspace name",
			toml:    wsToml("..", wsDir, "read", "[]"),
			wantSub: "name",
		},
		{
			name:    "duplicate workspace name",
			toml:    wsToml("app", wsDir, "read", "[]") + "\n" + wsToml("app", t.TempDir(), "read", "[]"),
			wantSub: "duplicate",
		},
		{
			name:    "relative workspace path",
			toml:    wsToml("app", "relative/path", "read", "[]"),
			wantSub: "absolute",
		},
		{
			name:    "nonexistent workspace path",
			toml:    wsToml("app", filepath.Join(wsDir, "missing"), "read", "[]"),
			wantSub: "workspace",
		},
		{
			name:    "workspace path is file",
			toml:    wsToml("app", filePath, "read", "[]"),
			wantSub: "directory",
		},
		{
			name:    "invalid max_perm",
			toml:    wsToml("app", wsDir, "admin", "[]"),
			wantSub: "max_perm",
		},
		{
			name:    "unknown check",
			toml:    wsToml("app", wsDir, "read", `["rm_rf"]`),
			wantSub: "check",
		},
		{
			name:    "redirect host with scheme",
			toml:    `public_url = "https://bridge.example.com"` + "\n" + `allow_redirect_hosts = ["https://evil.example.com"]`,
			wantSub: "allow_redirect_hosts",
		},
		{
			name:    "redirect host with path",
			toml:    `public_url = "https://bridge.example.com"` + "\n" + `allow_redirect_hosts = ["evil.example.com/cb"]`,
			wantSub: "allow_redirect_hosts",
		},
		{
			name:    "invalid deny glob",
			toml:    `public_url = "https://bridge.example.com"` + "\n" + `deny_patterns = ["["]`,
			wantSub: "deny_patterns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgPath, _ := writeConfigFile(t, tt.toml)
			_, err := config.Load(cfgPath)
			if err == nil {
				t.Fatalf("Load succeeded, want error containing %q", tt.wantSub)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantSub)) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestLoadAllowsHTTPPublicURLWithOption(t *testing.T) {
	cfgPath, _ := writeConfigFile(t, `public_url = "http://127.0.0.1:8787"`)
	if _, err := config.Load(cfgPath); err == nil {
		t.Fatal("Load without option succeeded, want https error")
	}
	cfg, err := config.LoadWithOptions(cfgPath, config.LoadOptions{AllowHTTPPublicURL: true})
	if err != nil {
		t.Fatalf("LoadWithOptions: %v", err)
	}
	if cfg.PublicURL != "http://127.0.0.1:8787" {
		t.Errorf("PublicURL = %q", cfg.PublicURL)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	cfgPath, _ := writeConfigFile(t, `public_url = "https://bridge.example.com"
deny_pattern = ["*.secret"]
leaky_credential = "SUPERSECRETVALUE"
`)
	_, err := config.Load(cfgPath)
	if err == nil {
		t.Fatal("Load accepted an unknown field")
	}
	for _, key := range []string{"deny_pattern", "leaky_credential"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error = %q, want mention of %s", err, key)
		}
	}
	if strings.Contains(err.Error(), "SUPERSECRETVALUE") {
		t.Errorf("error echoed an unknown field's value: %q", err)
	}
}

func TestHTTPPublicURLRequiresLoopbackListen(t *testing.T) {
	nonLoopback := []string{"0.0.0.0:8787", "192.168.1.10:8787", "bridge.example.com:8787", "[::]:8787"}
	for _, listen := range nonLoopback {
		cfgPath, _ := writeConfigFile(t, `public_url = "http://bridge.example.com"
listen = "`+listen+`"`)
		_, err := config.LoadWithOptions(cfgPath, config.LoadOptions{AllowHTTPPublicURL: true})
		if err == nil {
			t.Errorf("listen %q: LoadWithOptions succeeded, want error", listen)
			continue
		}
		if !strings.Contains(err.Error(), "loopback") {
			t.Errorf("listen %q: error = %q, want loopback mention", listen, err)
		}
	}

	loopback := []string{"127.0.0.1:8787", "127.0.0.2:8787", "[::1]:8787", "localhost:8787"}
	for _, listen := range loopback {
		cfgPath, _ := writeConfigFile(t, `public_url = "http://bridge.example.com"
listen = "`+listen+`"`)
		if _, err := config.LoadWithOptions(cfgPath, config.LoadOptions{AllowHTTPPublicURL: true}); err != nil {
			t.Errorf("listen %q: LoadWithOptions failed: %v", listen, err)
		}
	}
}

func TestPublicURLErrorsDoNotEchoCredentials(t *testing.T) {
	const credential = "leaky-credential-value"
	cases := []string{
		"https://user:" + credential + "@[::1",
		"https://user:" + credential + "@bridge.example.com/base",
	}
	for _, raw := range cases {
		cfgPath, _ := writeConfigFile(t, `public_url = "`+raw+`"`)
		_, err := config.Load(cfgPath)
		if err == nil {
			t.Errorf("public_url %q: Load succeeded, want error", raw)
			continue
		}
		if strings.Contains(err.Error(), credential) {
			t.Errorf("public_url error leaked credential: %q", err)
		}
	}
}

func TestSaveRoundTrip(t *testing.T) {
	wsDir := t.TempDir()
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "config.toml")

	cfg := &config.Config{
		PublicURL:            "https://bridge.example.com",
		Listen:               "127.0.0.1:8787",
		MaxSnapshotsPerGrant: 20,
		Workspaces: []config.Workspace{{
			Name:    "app",
			Path:    wsDir,
			MaxPerm: config.PermCheck,
			Checks:  []string{"git_status"},
		}},
	}
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("config mode = %o, want 600", got)
		}
		dirInfo, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if got := dirInfo.Mode().Perm(); got != 0o700 {
			t.Errorf("config dir mode = %o, want 700", got)
		}
	}

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if loaded.PublicURL != cfg.PublicURL || len(loaded.Workspaces) != 1 {
		t.Errorf("round trip mismatch: %+v", loaded)
	}
}

func TestWriteExampleIsLoadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wsbridge", "config.toml")
	if err := config.WriteExample(path); err != nil {
		t.Fatalf("WriteExample: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load example: %v", err)
	}
	if !strings.HasPrefix(cfg.PublicURL, "https://") {
		t.Errorf("example PublicURL = %q", cfg.PublicURL)
	}
	dataDir, err := cfg.ResolvedDataDir()
	if err != nil {
		t.Fatalf("ResolvedDataDir: %v", err)
	}
	if dataDir != filepath.Join(dir, "wsbridge") {
		t.Errorf("data dir = %q", dataDir)
	}
}

func TestDefaultPath(t *testing.T) {
	path, err := config.DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	if !filepath.IsAbs(path) {
		t.Errorf("DefaultPath = %q, want absolute", path)
	}
	wantSuffix := filepath.Join("wsbridge", "config.toml")
	if !strings.HasSuffix(path, wantSuffix) {
		t.Errorf("DefaultPath = %q, want suffix %q", path, wantSuffix)
	}
}

func TestPermissionValid(t *testing.T) {
	for _, p := range []config.Permission{config.PermRead, config.PermWrite, config.PermCheck} {
		if !p.Valid() {
			t.Errorf("%q.Valid() = false", p)
		}
	}
	for _, p := range []config.Permission{"", "none", "admin", "READ"} {
		if p.Valid() {
			t.Errorf("%q.Valid() = true", p)
		}
	}
}

func wsToml(name, path, maxPerm, checks string) string {
	return `public_url = "https://bridge.example.com"

[[workspace]]
name = "` + name + `"
path = "` + escapeTOML(path) + `"
max_perm = "` + maxPerm + `"
checks = ` + checks + "\n"
}

func escapeTOML(s string) string {
	return strings.ReplaceAll(s, `\`, `\\`)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTunnelConfigValidation(t *testing.T) {
	dir := t.TempDir()
	ws := "\n[[workspace]]\nname = \"app\"\npath = \"" + escapeTOML(dir) + "\"\nmax_perm = \"read\"\n"
	cases := []struct {
		name    string
		toml    string
		wantErr bool
	}{
		{
			name: "default empty provider",
			toml: "public_url = \"https://bridge.example.com\"" + ws,
		},
		{
			name: "none provider",
			toml: "public_url = \"https://bridge.example.com\"\n[tunnel]\nprovider = \"none\"\n" + ws,
		},
		{
			name: "cloudflared with token_file",
			toml: "public_url = \"https://bridge.example.com\"\n[tunnel]\nprovider = \"cloudflared\"\ntoken_file = \"/etc/cloudflared/token\"\n" + ws,
		},
		{
			name: "cloudflared with tilde token_file",
			toml: "public_url = \"https://bridge.example.com\"\n[tunnel]\nprovider = \"cloudflared\"\ntoken_file = \"~/cf-token\"\n" + ws,
		},
		{
			name: "cloudflared with token_env",
			toml: "public_url = \"https://bridge.example.com\"\n[tunnel]\nprovider = \"cloudflared\"\ntoken_env = \"CLOUDFLARE_TUNNEL_TOKEN\"\n" + ws,
		},
		{
			name:    "cloudflared missing token source",
			toml:    "public_url = \"https://bridge.example.com\"\n[tunnel]\nprovider = \"cloudflared\"\n" + ws,
			wantErr: true,
		},
		{
			name:    "cloudflared both token_file and token_env",
			toml:    "public_url = \"https://bridge.example.com\"\n[tunnel]\nprovider = \"cloudflared\"\ntoken_file = \"/etc/cloudflared/token\"\ntoken_env = \"CLOUDFLARE_TUNNEL_TOKEN\"\n" + ws,
			wantErr: true,
		},
		{
			name:    "cloudflared invalid token_env",
			toml:    "public_url = \"https://bridge.example.com\"\n[tunnel]\nprovider = \"cloudflared\"\ntoken_env = \"BAD=NAME\"\n" + ws,
			wantErr: true,
		},
		{
			name:    "unknown provider",
			toml:    "public_url = \"https://bridge.example.com\"\n[tunnel]\nprovider = \"ngrok\"\n" + ws,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.toml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got cfg=%+v", cfg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Tunnel.Provider == "cloudflared" && cfg.Tunnel.Binary != "cloudflared" {
				t.Fatalf("default Tunnel.Binary = %q, want %q", cfg.Tunnel.Binary, "cloudflared")
			}
		})
	}
}
