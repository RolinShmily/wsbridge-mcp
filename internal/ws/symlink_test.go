package ws_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"wsbridge/internal/ws"
)

// A symlink inside the workspace must not become a portal to a sensitive path
// such as .git: os.Root resolves in-root links, so the lexical denylist alone
// would be bypassed by e.g. "leaks -> .git".
func TestSymlinkedDirectoryCannotBypassDenylist(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows")
	}
	rootDir := t.TempDir()
	gitDir := filepath.Join(rootDir, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte("[core]"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".git", filepath.Join(rootDir, "leaks")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(rootDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.git", filepath.Join(rootDir, "sub", "leaks")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(rootDir, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, "real", "note.txt"), []byte("note"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(rootDir, "alias")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	for _, p := range []string{"leaks/config", "sub/leaks/config"} {
		data, _, err := w.ReadFile(p)
		if !errors.Is(err, ws.ErrDeniedPath) {
			t.Errorf("ReadFile(%q) error = %v, want ErrDeniedPath", p, err)
		}
		if len(data) != 0 {
			t.Errorf("ReadFile(%q) leaked %q", p, data)
		}
		if _, _, err := w.WriteFileAtomic("grant1", p, []byte("x"), "", false); !errors.Is(err, ws.ErrDeniedPath) {
			t.Errorf("WriteFileAtomic(%q) error = %v, want ErrDeniedPath", p, err)
		}
	}
	if _, _, err := w.WriteFileAtomic("grant1", "leaks/hooks/pre-commit", []byte("x"), "", false); !errors.Is(err, ws.ErrDeniedPath) {
		t.Errorf("WriteFileAtomic through symlink error = %v, want ErrDeniedPath", err)
	}
	if _, err := os.Stat(filepath.Join(gitDir, "hooks", "pre-commit")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("write through symlink reached .git: %v", err)
	}

	// All symlinked directories are skipped, even when the target itself is
	// allowed; this keeps the tree/search views consistent with the policy.
	if data, _, err := w.ReadFile("alias/note.txt"); !errors.Is(err, ws.ErrDeniedPath) {
		t.Errorf("ReadFile(alias/note.txt) error = %v, want ErrDeniedPath (data %q)", err, data)
	}
	if _, _, err := w.Search(t.Context(), ws.SearchOptions{Query: "note", Subdir: "leaks"}); !errors.Is(err, ws.ErrNotRegularFile) {
		t.Errorf("Search in symlinked subdir error = %v, want ErrNotRegularFile", err)
	}
	if _, _, err := w.Search(t.Context(), ws.SearchOptions{Query: "note", Subdir: "alias"}); !errors.Is(err, ws.ErrNotRegularFile) {
		t.Errorf("Search in allowed-target symlink error = %v, want ErrNotRegularFile", err)
	}
	if _, err := w.WalkTree("leaks", 2, "", 10); err == nil {
		t.Error("WalkTree followed a symlinked directory")
	}

	// A regular file used as a directory component is rejected before I/O.
	if _, _, err := w.ReadFile("real/note.txt/x"); !errors.Is(err, ws.ErrInvalidPath) {
		t.Errorf("ReadFile through regular file error = %v, want ErrInvalidPath", err)
	}
}
