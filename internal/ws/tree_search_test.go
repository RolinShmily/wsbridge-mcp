package ws_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/RolinShmily/wsbridge-mcp/internal/ws"
)

func buildTree(t *testing.T) string {
	t.Helper()
	rootDir := t.TempDir()
	files := map[string]string{
		"a.txt":               "a",
		"dir/b.go":            "package dir",
		"dir/nested/c.txt":    "c",
		"node_modules/pkg.js": "module",
		"dist/bundle.js":      "bundle",
		".env":                "SECRET=1",
		".git/config":         "[core]",
		"visible/.gitignore":  "ignored",
		"visible/.ssh/id_rsa": "PRIVATE",
		"visible/keep.txt":    "keep",
	}
	for rel, content := range files {
		full := filepath.Join(rootDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return rootDir
}

func TestWalkTreeFiltersAndOrders(t *testing.T) {
	rootDir := buildTree(t)
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	res, err := w.WalkTree("", 3, "", 100)
	if err != nil {
		t.Fatalf("WalkTree: %v", err)
	}
	got := map[string]bool{}
	for _, entry := range res.Entries {
		got[entry.Path] = entry.IsDir
	}
	for _, want := range []string{"a.txt", "dir", "dir/b.go", "dir/nested", "dir/nested/c.txt", "visible", "visible/.gitignore", "visible/keep.txt"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing entry %q in %v", want, got)
		}
	}
	for _, hidden := range []string{".env", ".git", ".git/config", "node_modules", "node_modules/pkg.js", "dist", "visible/.ssh", "visible/.ssh/id_rsa"} {
		if _, ok := got[hidden]; ok {
			t.Errorf("hidden entry %q was listed", hidden)
		}
	}
	if !got["dir"] || got["a.txt"] {
		t.Errorf("IsDir flags wrong: %v", got)
	}
}

func TestWalkTreeDepthLimit(t *testing.T) {
	rootDir := buildTree(t)
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	res, err := w.WalkTree("", 1, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range res.Entries {
		if strings.Contains(entry.Path, "/") {
			t.Errorf("depth 1 returned nested entry %q", entry.Path)
		}
	}
}

func TestWalkTreePagination(t *testing.T) {
	rootDir := buildTree(t)
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		res, err := w.WalkTree("", 3, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range res.Entries {
			if seen[entry.Path] {
				t.Errorf("duplicate entry %q across pages", entry.Path)
			}
			seen[entry.Path] = true
		}
		pages++
		if res.NextCursor == "" {
			break
		}
		cursor = res.NextCursor
		if pages > 20 {
			t.Fatal("pagination did not terminate")
		}
	}
	if pages < 3 {
		t.Errorf("pages = %d, want several", pages)
	}
	if !seen["dir/nested/c.txt"] {
		t.Errorf("pagination missed dir/nested/c.txt: %v", seen)
	}
}

func TestWalkTreeRejectsBadInputs(t *testing.T) {
	rootDir := buildTree(t)
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	if _, err := w.WalkTree("a.txt", 3, "", 10); !errors.Is(err, ws.ErrNotRegularFile) {
		t.Errorf("file path error = %v, want ErrNotRegularFile", err)
	}
	if _, err := w.WalkTree(".git", 3, "", 10); !errors.Is(err, ws.ErrDeniedPath) {
		t.Errorf("denied path error = %v, want ErrDeniedPath", err)
	}
	if _, err := w.WalkTree("", 0, "", 10); err == nil {
		t.Error("depth 0 accepted")
	}
	if _, err := w.WalkTree("", 3, "not-a-number", 10); err == nil {
		t.Error("invalid cursor accepted")
	}
}

func TestWalkTreeSkipsSymlinkedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows")
	}
	rootDir := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("TOP SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rootDir, "escape_dir")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	res, err := w.WalkTree("", 5, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range res.Entries {
		if strings.Contains(entry.Path, "escape_dir") || strings.Contains(entry.Path, "secret") {
			t.Errorf("symlink escape appeared in tree: %q", entry.Path)
		}
	}
}

func TestSearchLiteralRegexAndCase(t *testing.T) {
	rootDir := t.TempDir()
	files := map[string]string{
		"a.txt":             "hello world\nsecond line\n",
		"b.go":              "Hello Go\n",
		"sub/c.txt":         "hello nested\n",
		".env":              "hello secret\n",
		"node_modules/x.js": "hello heavy\n",
		"binary.bin":        "hello\x00binary",
	}
	for rel, content := range files {
		full := filepath.Join(rootDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()
	ctx := context.Background()

	matches, truncated, err := w.Search(ctx, ws.SearchOptions{Query: "hello", IgnoreCase: true, MaxResults: 100})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if truncated {
		t.Error("unexpected truncation")
	}
	paths := matchPaths(matches)
	for _, want := range []string{"a.txt", "b.go", "sub/c.txt"} {
		if !paths[want] {
			t.Errorf("missing match %q in %v", want, paths)
		}
	}
	for _, hidden := range []string{".env", "node_modules/x.js", "binary.bin"} {
		if paths[hidden] {
			t.Errorf("hidden/binary file matched: %q", hidden)
		}
	}

	matches, _, err = w.Search(ctx, ws.SearchOptions{Query: "h.llo", MaxResults: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("literal search matched regex metacharacter: %v", matches)
	}
	matches, _, err = w.Search(ctx, ws.SearchOptions{Query: "hel+o", Regex: true, MaxResults: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !matchPaths(matches)["a.txt"] || matchPaths(matches)["b.go"] {
		t.Errorf("case-sensitive regex results = %v, want lowercase matches only", matches)
	}
	matches, _, err = w.Search(ctx, ws.SearchOptions{Query: "hel+o", Regex: true, IgnoreCase: true, MaxResults: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Error("case-insensitive regex matched nothing")
	}

	matches, _, err = w.Search(ctx, ws.SearchOptions{Query: "hello", IgnoreCase: false, MaxResults: 100})
	if err != nil {
		t.Fatal(err)
	}
	if matchPaths(matches)["b.go"] {
		t.Error("case-sensitive search matched Hello")
	}
}

func TestSearchSubdirAndPagination(t *testing.T) {
	rootDir := t.TempDir()
	for rel, content := range map[string]string{
		"a.txt":     "needle\n",
		"sub/b.txt": "needle\nneedle\n",
		"sub/c.txt": "needle\n",
	} {
		full := filepath.Join(rootDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	matches, _, err := w.Search(context.Background(), ws.SearchOptions{Query: "needle", Subdir: "sub", MaxResults: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no matches in subdir")
	}
	for _, m := range matches {
		if !strings.HasPrefix(m.Path, "sub/") {
			t.Errorf("match outside subdir: %q", m.Path)
		}
	}

	matches, truncated, err := w.Search(context.Background(), ws.SearchOptions{Query: "needle", MaxResults: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || !truncated {
		t.Errorf("max_results=1: len=%d truncated=%v", len(matches), truncated)
	}

	if _, _, err := w.Search(context.Background(), ws.SearchOptions{Query: "needle", Subdir: ".git"}); !errors.Is(err, ws.ErrDeniedPath) {
		t.Errorf("denied subdir error = %v", err)
	}
	if _, _, err := w.Search(context.Background(), ws.SearchOptions{Query: "needle", Subdir: "../x"}); !errors.Is(err, ws.ErrInvalidPath) {
		t.Errorf("escaping subdir error = %v", err)
	}
}

func TestSearchHonorsCanceledContext(t *testing.T) {
	rootDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootDir, "a.txt"), []byte("needle\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := w.Search(ctx, ws.SearchOptions{Query: "needle"}); !errors.Is(err, context.Canceled) {
		t.Errorf("Search with canceled context error = %v, want context.Canceled", err)
	}
}

func TestSearchWithRipgrep(t *testing.T) {
	if _, err := os.Stat("/usr/bin/rg"); err != nil {
		t.Skip("ripgrep not installed")
	}
	rootDir := t.TempDir()
	for rel, content := range map[string]string{
		"a.txt":             "needle\n",
		"skip/.env":         "needle secret\n",
		"node_modules/x.js": "needle heavy\n",
	} {
		full := filepath.Join(rootDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dataDir := t.TempDir()
	mgr := newTestManager(t, []ws.WorkspaceConfig{{Name: "app", Path: rootDir, MaxPerm: ws.PermRead}},
		ws.ManagerOptions{DataDir: dataDir}) // auto-detect rg
	defer mgr.Close()
	w, _ := mgr.Get("app")

	matches, _, err := w.Search(context.Background(), ws.SearchOptions{Query: "needle", MaxResults: 100})
	if err != nil {
		t.Fatalf("Search with rg: %v", err)
	}
	for _, m := range matches {
		if strings.Contains(m.Path, ".env") || strings.Contains(m.Path, "node_modules") {
			t.Errorf("ripgrep result bypassed denylist: %q", m.Path)
		}
	}
	if !matchPaths(matches)["a.txt"] {
		t.Errorf("ripgrep missed a.txt: %v", matches)
	}
}

func matchPaths(matches []ws.SearchMatch) map[string]bool {
	out := make(map[string]bool, len(matches))
	for _, m := range matches {
		out[m.Path] = true
	}
	return out
}
