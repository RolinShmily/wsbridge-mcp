package ws_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"wsbridge/internal/ws"
)

func newSingleWorkspace(t *testing.T, rootDir string) (*ws.Manager, *ws.Workspace, string) {
	t.Helper()
	dataDir := t.TempDir()
	mgr := newTestManager(t, []ws.WorkspaceConfig{{
		Name:    "app",
		Path:    rootDir,
		MaxPerm: ws.PermCheck,
		Checks:  []string{"git_status", "git_diff"},
	}}, ws.ManagerOptions{DataDir: dataDir, RipgrepPath: "none"})
	w, ok := mgr.Get("app")
	if !ok {
		t.Fatal("workspace app missing")
	}
	return mgr, w, dataDir
}

func TestReadFileReturnsContentAndHash(t *testing.T) {
	rootDir := t.TempDir()
	content := []byte("hello world\n")
	if err := os.WriteFile(filepath.Join(rootDir, "hello.txt"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	got, hash, err := w.ReadFile("hello.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content = %q", got)
	}
	sum := sha256.Sum256(content)
	if want := hex.EncodeToString(sum[:]); hash != want {
		t.Errorf("hash = %q, want %q", hash, want)
	}
}

func TestReadFileRejectsDeniedPaths(t *testing.T) {
	rootDir := t.TempDir()
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	denied := []string{
		".git/config",
		".ssh/authorized_keys",
		".env",
		".env.local",
		"id_ed25519",
		"cert.pem",
		"sub/.aws/credentials",
		"CON",
		"file.txt:ads",
		"../outside",
		"/etc/passwd",
		`C:\Windows\System32`,
	}
	for _, p := range denied {
		if _, _, err := w.ReadFile(p); err == nil {
			t.Errorf("ReadFile(%q) succeeded, want error", p)
		}
	}
}

func TestReadFileRejectsLargeFile(t *testing.T) {
	rootDir := t.TempDir()
	path := filepath.Join(rootDir, "big.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), ws.MaxFileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	if _, _, err := w.ReadFile("big.bin"); !errors.Is(err, ws.ErrFileTooLarge) {
		t.Fatalf("error = %v, want ErrFileTooLarge", err)
	}
}

func TestReadFileRejectsDirectory(t *testing.T) {
	rootDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootDir, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	if _, _, err := w.ReadFile("dir"); !errors.Is(err, ws.ErrNotRegularFile) {
		t.Fatalf("error = %v, want ErrNotRegularFile", err)
	}
}

func TestReadFileBlocksSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows")
	}
	rootDir := t.TempDir()
	outsideDir := t.TempDir()
	secretPath := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("TOP SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secretPath, filepath.Join(rootDir, "escape_link")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	data, _, err := w.ReadFile("escape_link")
	if err == nil {
		t.Fatalf("ReadFile followed escape symlink: %q", data)
	}
	if strings.Contains(string(data), "TOP SECRET") {
		t.Fatal("secret content leaked through symlink")
	}
}

func TestManagerRejectsInvalidConfiguration(t *testing.T) {
	rootDir := t.TempDir()
	tests := []struct {
		name    string
		configs []ws.WorkspaceConfig
		opts    ws.ManagerOptions
		wantSub string
	}{
		{
			name:    "missing data dir",
			configs: []ws.WorkspaceConfig{{Name: "app", Path: rootDir, MaxPerm: ws.PermRead}},
			opts:    ws.ManagerOptions{},
			wantSub: "data directory",
		},
		{
			name: "duplicate name",
			configs: []ws.WorkspaceConfig{
				{Name: "app", Path: rootDir, MaxPerm: ws.PermRead},
				{Name: "app", Path: rootDir, MaxPerm: ws.PermRead},
			},
			opts:    ws.ManagerOptions{DataDir: t.TempDir()},
			wantSub: "duplicate",
		},
		{
			name:    "missing path",
			configs: []ws.WorkspaceConfig{{Name: "app", Path: filepath.Join(rootDir, "missing"), MaxPerm: ws.PermRead}},
			opts:    ws.ManagerOptions{DataDir: t.TempDir()},
			wantSub: "open workspace",
		},
		{
			name:    "invalid permission",
			configs: []ws.WorkspaceConfig{{Name: "app", Path: rootDir, MaxPerm: ws.PermNone}},
			opts:    ws.ManagerOptions{DataDir: t.TempDir()},
			wantSub: "permission",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ws.NewManager(tt.configs, tt.opts)
			if err == nil {
				t.Fatal("NewManager succeeded, want error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantSub)) {
				t.Errorf("error = %q, want substring %q", err, tt.wantSub)
			}
		})
	}
}

func TestPermissionHelpers(t *testing.T) {
	for _, s := range []string{"read", "write", "check"} {
		p, err := ws.ParsePermission(s)
		if err != nil {
			t.Errorf("ParsePermission(%q): %v", s, err)
		}
		if p.String() != s {
			t.Errorf("Permission.String() = %q, want %q", p.String(), s)
		}
	}
	if _, err := ws.ParsePermission("admin"); err == nil {
		t.Error("ParsePermission(admin) succeeded")
	}
	if got := ws.MinPermission(ws.PermCheck, ws.PermRead); got != ws.PermRead {
		t.Errorf("MinPermission = %v, want read", got)
	}
}
