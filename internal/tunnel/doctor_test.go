package tunnel_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RolinShmily/wsbridge-mcp/internal/audit"
	"github.com/RolinShmily/wsbridge-mcp/internal/config"
	"github.com/RolinShmily/wsbridge-mcp/internal/mcpsrv"
	"github.com/RolinShmily/wsbridge-mcp/internal/oauth"
	"github.com/RolinShmily/wsbridge-mcp/internal/tunnel"
	"github.com/RolinShmily/wsbridge-mcp/internal/ws"
)

func startStack(t *testing.T) (issuer, dataDir, wsDir string, closeStack func()) {
	t.Helper()
	dataDir = t.TempDir()
	wsDir = t.TempDir()
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wsDir, "a.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr, err := ws.NewManager([]ws.WorkspaceConfig{{
		Name: "app", Path: wsDir, MaxPerm: ws.PermRead,
	}}, ws.ManagerOptions{DataDir: dataDir, RipgrepPath: "none"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	issuer = "http://" + server.Listener.Addr().String()

	store, err := oauth.OpenStore(filepath.Join(dataDir, "wsbridge.db"), oauth.StoreOptions{Issuer: issuer})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := oauth.HashAdminPassphrase("doctor-test-passphrase", oauth.Argon2Params{
		Memory: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetAdminHash(hash); err != nil {
		t.Fatal(err)
	}
	auditLogger, err := audit.Open(filepath.Join(dataDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := oauth.New(oauth.Config{
		Issuer: issuer, Store: store, Audit: auditLogger,
		Workspaces: []oauth.WorkspaceChoice{{Name: "app", Path: wsDir, MaxPerm: ws.PermRead}},
	})
	if err != nil {
		t.Fatal(err)
	}
	auth.Mount(mux)
	mcpServer, err := mcpsrv.New(mcpsrv.Options{
		Manager: mgr,
		Version: "doctor-test",
		Scope:   mcpsrv.GrantScope(mgr),
		Auth: &mcpsrv.AuthConfig{
			Verifier: store, ResourceURL: auth.ResourceURL(), ResourceMetadataURL: auth.ResourceMetadataURL(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mcpServer.Mount(mux)
	server.Start()
	closeStack = func() {
		server.Close()
		_ = auditLogger.Close()
		_ = store.Close()
		_ = mgr.Close()
	}
	return issuer, dataDir, wsDir, closeStack
}

func testConfig(issuer, dataDir, wsDir string) *config.Config {
	return &config.Config{
		PublicURL: issuer,
		Listen:    "127.0.0.1:8787",
		DataDir:   dataDir,
		Workspaces: []config.Workspace{{
			Name: "app", Path: wsDir, MaxPerm: config.PermRead,
		}},
	}
}

func runDoctor(t *testing.T, cfg *config.Config, dataDir string) []tunnel.Check {
	t.Helper()
	return tunnel.Run(context.Background(), tunnel.Options{
		Config:  cfg,
		DataDir: dataDir,
		Timeout: 3 * time.Second,
		Client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		LookPath: func(string) (string, error) { return "", os.ErrNotExist },
	})
}

func TestDoctorHealthyStack(t *testing.T) {
	issuer, dataDir, wsDir, closeStack := startStack(t)
	defer closeStack()
	checks := runDoctor(t, testConfig(issuer, dataDir, wsDir), dataDir)
	if tunnel.Failed(checks) {
		for _, c := range checks {
			t.Logf("[%s] %s: %s", c.Level, c.Name, c.Detail)
		}
		t.Fatal("healthy stack reported a critical issue")
	}
	passing := map[string]bool{}
	for _, c := range checks {
		if c.Level == tunnel.Pass {
			passing[c.Name] = true
		}
	}
	for _, name := range []string{
		"data directory", "public PRM", "public AS metadata", "public /mcp", "public /mcp/", "public DCR",
	} {
		if !passing[name] {
			t.Errorf("check %q did not pass", name)
		}
	}
	// The database is held open by the running server, so the passphrase
	// check must degrade to WARN rather than fail.
	for _, c := range checks {
		if c.Name == "oauth database" && c.Level == tunnel.Fail {
			t.Errorf("locked database was reported as a failure: %s", c.Detail)
		}
	}
}

func TestDoctorDetectsTunnelRedirect(t *testing.T) {
	issuer, dataDir, wsDir, closeStack := startStack(t)
	defer closeStack()

	// Point the config at a proxy that redirects /mcp.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			http.Redirect(w, r, "/mcp-real", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer proxy.Close()

	cfg := testConfig(issuer, dataDir, wsDir)
	cfg.PublicURL = proxy.URL
	checks := runDoctor(t, cfg, dataDir)
	if !tunnel.Failed(checks) {
		t.Fatal("redirecting proxy was not reported")
	}
	found := false
	for _, c := range checks {
		if c.Level == tunnel.Fail && strings.Contains(c.Detail, "redirect") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no redirect failure: %+v", checks)
	}
}

func TestDoctorDetectsMissingDatabase(t *testing.T) {
	checks := tunnel.Run(context.Background(), tunnel.Options{
		DataDir:  t.TempDir(),
		Timeout:  time.Second,
		LookPath: func(string) (string, error) { return "", os.ErrNotExist },
	})
	if !tunnel.Failed(checks) {
		t.Fatal("missing database was not reported")
	}
	found := false
	for _, c := range checks {
		if c.Level == tunnel.Fail && strings.Contains(c.Detail, "passwd") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no passphrase failure: %+v", checks)
	}
}

func TestDoctorDetectsUnreachablePublicURL(t *testing.T) {
	_, dataDir, wsDir, closeStack := startStack(t)
	defer closeStack()
	cfg := testConfig("http://127.0.0.1:1", dataDir, wsDir)
	checks := tunnel.Run(context.Background(), tunnel.Options{
		Config: cfg, DataDir: dataDir, Timeout: 300 * time.Millisecond,
		LookPath: func(string) (string, error) { return "", os.ErrNotExist },
	})
	if !tunnel.Failed(checks) {
		t.Fatal("unreachable public URL was not reported")
	}
}
