package ws_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/RolinShmily/wsbridge-mcp/internal/ws"
)

func TestDeriveWorkspaceName(t *testing.T) {
	cases := []struct {
		dir  string
		want string
	}{
		{filepath.Join("C:", "Users", "me", "my-project"), "my-project"},
		{filepath.Join("C:", "Users", "me", "My App (v2)"), "My-App-v2"},
		{filepath.Join("C:", "Users", "me", "proj_1.2"), "proj_1.2"},
		{filepath.Join("C:", "Users", "me", "中文项目"), "workspace"},
		{filepath.Join("C:", "Users", "me", "..."), "workspace"},
		{"", "workspace"},
	}
	for _, tc := range cases {
		got := ws.DeriveWorkspaceName(tc.dir)
		if got != tc.want {
			t.Errorf("DeriveWorkspaceName(%q) = %q, want %q", tc.dir, got, tc.want)
		}
	}
}

func TestBuiltinChecksExpandedAndEnabledByDefault(t *testing.T) {
	names := ws.BuiltinCheckNames()
	for _, want := range []string{
		"git_status", "git_diff", "git_log",
		"go_vet", "go_test", "go_build",
		"npm_lint", "npm_test", "npm_build",
		"pytest", "ruff_check", "mypy",
		"uv_pytest", "uv_ruff", "uv_mypy", "uv_lock_check",
		"uv_pip_list", "uv_pip_check",
		"pip_list", "pip_check",
		"cargo_check", "cargo_test",
	} {
		if !ws.KnownCheck(want) {
			t.Errorf("KnownCheck(%q) = false, want true", want)
		}
		if !slices.Contains(names, want) {
			t.Errorf("BuiltinCheckNames() missing %q", want)
		}
	}
	if ws.KnownCheck("rm_rf") {
		t.Error("KnownCheck(rm_rf) = true, want false")
	}

	dir := t.TempDir()
	mgr, err := ws.NewManager([]ws.WorkspaceConfig{{
		Name:    "app",
		Path:    dir,
		MaxPerm: ws.PermCheck,
		// Checks intentionally empty: all built-in checks are allowed by default.
	}}, ws.ManagerOptions{DataDir: t.TempDir(), RipgrepPath: "none"})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	w, ok := mgr.Get("app")
	if !ok {
		t.Fatal("workspace app missing")
	}
	allowed := w.AllowedChecks()
	if !slices.Equal(allowed, names) {
		t.Errorf("AllowedChecks() = %v, want all built-in checks %v", allowed, names)
	}
}

func TestManagerAllowsZeroWorkspacesAndHotSwitches(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirA, "from_a.txt"), []byte("alpha\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirB, "from_b.txt"), []byte("beta\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	mgr, err := ws.NewManager(nil, ws.ManagerOptions{DataDir: t.TempDir(), RipgrepPath: "none"})
	if err != nil {
		t.Fatalf("NewManager(nil): %v", err)
	}
	defer mgr.Close()
	if got := mgr.Workspaces(); len(got) != 0 {
		t.Fatalf("initial Workspaces = %d, want 0", len(got))
	}

	active, err := mgr.SetActive(ws.WorkspaceConfig{Name: "proj-a", Path: dirA, MaxPerm: ws.PermCheck})
	if err != nil {
		t.Fatalf("SetActive(proj-a): %v", err)
	}
	if active.Name() != "proj-a" || active.HostPath() != dirA {
		t.Fatalf("active = %q (%q)", active.Name(), active.HostPath())
	}
	data, _, err := active.ReadFile("from_a.txt")
	if err != nil || string(data) != "alpha\n" {
		t.Fatalf("ReadFile(from_a.txt) = %q, %v", data, err)
	}

	// Concurrent readers while switching to proj-b must not race.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				for _, w := range mgr.Workspaces() {
					_, _, _ = w.ReadFile("from_a.txt")
					_, _, _ = w.ReadFile("from_b.txt")
					_, _, _ = w.Search(context.Background(), ws.SearchOptions{Query: "a"})
				}
			}
		}()
	}

	activeB, err := mgr.SetActive(ws.WorkspaceConfig{Name: "proj-b", Path: dirB, MaxPerm: ws.PermWrite})
	if err != nil {
		t.Fatalf("SetActive(proj-b): %v", err)
	}
	wg.Wait()

	if activeB.Name() != "proj-b" || activeB.MaxPerm() != ws.PermWrite {
		t.Fatalf("activeB = %q perm=%v", activeB.Name(), activeB.MaxPerm())
	}
	if _, ok := mgr.Get("proj-a"); ok {
		t.Error("old workspace proj-a still present after SetActive")
	}
	if w, ok := mgr.Get("proj-b"); !ok {
		t.Fatal("proj-b not present after SetActive")
	} else {
		got, _, err := w.ReadFile("from_b.txt")
		if err != nil || string(got) != "beta\n" {
			t.Fatalf("ReadFile(from_b.txt) = %q, %v", got, err)
		}
	}

	// Failed switch leaves existing active workspace intact.
	if _, err := mgr.SetActive(ws.WorkspaceConfig{
		Name: "missing", Path: filepath.Join(dirB, "does-not-exist"), MaxPerm: ws.PermCheck,
	}); err == nil {
		t.Fatal("SetActive with nonexistent path succeeded")
	}
	if _, ok := mgr.Get("proj-b"); !ok {
		t.Error("proj-b was lost after failed SetActive")
	}
}
