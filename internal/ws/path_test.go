package ws_test

import (
	"strings"
	"testing"

	"github.com/RolinShmily/wsbridge-mcp/internal/ws"
)

func TestSanitizeRelPathValid(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "."},
		{".", "."},
		{"a.txt", "a.txt"},
		{"a/b/c", "a/b/c"},
		{`a\b\c`, "a/b/c"},
		{"a//b/./c", "a/b/c"},
		{"dir/", "dir"},
		{"文档/说明.txt", "文档/说明.txt"},
	}
	for _, tt := range tests {
		got, err := ws.SanitizeRelPath(tt.in)
		if err != nil {
			t.Errorf("SanitizeRelPath(%q) error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("SanitizeRelPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSanitizeRelPathRejectsEscapes(t *testing.T) {
	tests := []string{
		"../secret.txt",
		"a/../../b",
		"a/..",
		"..",
		"/etc/passwd",
		`C:\Windows\System32`,
		`\\server\share`,
		"file.txt:ads",
		"a\x00b",
		"CON",
		"NUL.txt",
		"COM1",
		"lpt9.log",
		"aux",
		"con ",
		"con.",
		"a/COM2/b",
		"a/./../b",
		"CONIN$",
		"COM¹",
		"LPT².txt",
	}
	for _, in := range tests {
		if got, err := ws.SanitizeRelPath(in); err == nil {
			t.Errorf("SanitizeRelPath(%q) = %q, want error", in, got)
		}
	}
}

func TestIsDeniedPathDefaults(t *testing.T) {
	denied := []string{
		".git/config",
		"sub/.git/config",
		".ssh/authorized_keys",
		"sub/.ssh/id_rsa",
		".aws/credentials",
		".env",
		"sub/.env",
		".env.local",
		"sub/.env.production",
		".npmrc",
		".netrc",
		"id_rsa",
		"id_rsa.pub",
		"id_ed25519",
		"id_ed25519.pub",
		"cert.pem",
		"server.key",
		"bundle.p12",
		"cert.pfx",
		"vault.kdbx",
		"sub/CONFIG.PEM",
		".GIT/config",
		"ID_RSA",
	}
	for _, p := range denied {
		if !ws.IsDeniedPath(p) {
			t.Errorf("IsDeniedPath(%q) = false, want true", p)
		}
	}

	allowed := []string{
		"",
		".",
		"env",
		"gitignore",
		"README.md",
		"src/.gitignore",
		"app.pem.txt",
		"notes.txt",
		"docs/index.md",
	}
	for _, p := range allowed {
		if ws.IsDeniedPath(p) {
			t.Errorf("IsDeniedPath(%q) = true, want false", p)
		}
	}
}

func TestWorkspaceCustomDenyPatterns(t *testing.T) {
	mgr := newTestManager(t, []ws.WorkspaceConfig{{
		Name:    "app",
		Path:    t.TempDir(),
		MaxPerm: ws.PermWrite,
	}}, ws.ManagerOptions{
		DataDir:      t.TempDir(),
		DenyPatterns: []string{"*.secret", "private/*"},
	})
	defer mgr.Close()
	root, ok := mgr.Get("app")
	if !ok {
		t.Fatal("workspace not found")
	}
	for _, p := range []string{"token.secret", "a/b/token.secret", "private/notes.txt"} {
		if !root.IsDenied(p) {
			t.Errorf("IsDenied(%q) = false, want true", p)
		}
	}
	if root.IsDenied("public/notes.txt") {
		t.Error("public/notes.txt unexpectedly denied")
	}
}

func TestWorkspaceDenyPatternDoubleStar(t *testing.T) {
	mgr := newTestManager(t, []ws.WorkspaceConfig{{
		Name:    "app",
		Path:    t.TempDir(),
		MaxPerm: ws.PermWrite,
	}}, ws.ManagerOptions{
		DataDir:      t.TempDir(),
		DenyPatterns: []string{"**/*.secret", "cache/**"},
	})
	defer mgr.Close()
	root, ok := mgr.Get("app")
	if !ok {
		t.Fatal("workspace not found")
	}
	for _, p := range []string{"a/b/c.secret", "c.secret", "cache/x", "cache/x/y"} {
		if !root.IsDenied(p) {
			t.Errorf("IsDenied(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"a/b/c.secret.bak", "public/x.txt", "cached/x"} {
		if root.IsDenied(p) {
			t.Errorf("IsDenied(%q) = true, want false", p)
		}
	}
}

func TestWorkspaceRejectsInvalidCheck(t *testing.T) {
	_, err := ws.NewManager([]ws.WorkspaceConfig{{
		Name:    "app",
		Path:    t.TempDir(),
		MaxPerm: ws.PermCheck,
		Checks:  []string{"rm_rf"},
	}}, ws.ManagerOptions{DataDir: t.TempDir()})
	if err == nil {
		t.Fatal("NewManager accepted an unknown check")
	}
	if !strings.Contains(err.Error(), "unknown check") {
		t.Errorf("error = %q", err)
	}
}
