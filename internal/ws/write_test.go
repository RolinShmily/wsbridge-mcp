package ws_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"wsbridge/internal/ws"
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func TestWriteFileCreatesNewFile(t *testing.T) {
	rootDir := t.TempDir()
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	hash, snapshot, err := w.WriteFileAtomic("grant1", "nested/dir/new.txt", []byte("hello\n"), "", true)
	if err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	if snapshot != "" {
		t.Errorf("snapshot = %q, want empty for new file", snapshot)
	}
	data, readHash, err := w.ReadFile("nested/dir/new.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "hello\n" {
		t.Errorf("content = %q", data)
	}
	if hash != readHash {
		t.Errorf("returned hash %q != re-read hash %q", hash, readHash)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(rootDir, "nested/dir/new.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o644 {
			t.Errorf("new file mode = %o, want 644", got)
		}
	}
}

func TestWriteRejectsCreateOnlyOverwrite(t *testing.T) {
	rootDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootDir, "a.txt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	_, _, err := w.WriteFileAtomic("grant1", "a.txt", []byte("new"), "", true)
	if !errors.Is(err, ws.ErrFileExists) {
		t.Fatalf("error = %v, want ErrFileExists", err)
	}
	data, err := os.ReadFile(filepath.Join(rootDir, "a.txt"))
	if err != nil || string(data) != "old" {
		t.Fatalf("file changed: %q, %v", data, err)
	}
}

func TestWriteRequiresExpectedHashToOverwrite(t *testing.T) {
	rootDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootDir, "a.txt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	if _, _, err := w.WriteFileAtomic("grant1", "a.txt", []byte("new"), "", false); !errors.Is(err, ws.ErrMissingChecksum) {
		t.Fatalf("error = %v, want ErrMissingChecksum", err)
	}
	if _, _, err := w.WriteFileAtomic("grant1", "a.txt", []byte("new"), "deadbeef", false); !errors.Is(err, ws.ErrChecksumMismatch) {
		t.Fatalf("error = %v, want ErrChecksumMismatch", err)
	}
	if _, _, err := w.WriteFileAtomic("grant1", "missing.txt", []byte("new"), "deadbeef", false); !errors.Is(err, ws.ErrChecksumForMissing) {
		t.Fatalf("error = %v, want ErrChecksumForMissing", err)
	}
}

func TestWriteOverwriteCreatesSnapshot(t *testing.T) {
	rootDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootDir, "a.txt"), []byte("old content"), 0o640); err != nil {
		t.Fatal(err)
	}
	mgr, w, dataDir := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	_, oldHash, err := w.ReadFile("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	newHash, snapshotRel, err := w.WriteFileAtomic("grant1", "a.txt", []byte("new content"), oldHash, false)
	if err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	if snapshotRel == "" {
		t.Fatal("snapshot path is empty")
	}
	snapshotPath := filepath.Join(dataDir, "snapshots", filepath.FromSlash(snapshotRel))
	snapshot, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatalf("read snapshot %q: %v", snapshotPath, err)
	}
	if string(snapshot) != "old content" {
		t.Errorf("snapshot content = %q", snapshot)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(rootDir, "a.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o640 {
			t.Errorf("mode = %o, want 640", got)
		}
	}
	data, readHash, err := w.ReadFile("a.txt")
	if err != nil || string(data) != "new content" || readHash != newHash {
		t.Fatalf("post-write read = %q hash=%q err=%v", data, readHash, err)
	}
}

func TestWritePreservesBOMAndCRLF(t *testing.T) {
	rootDir := t.TempDir()
	original := append(append([]byte{}, utf8BOM...), []byte("line1\r\nline2\r\n")...)
	if err := os.WriteFile(filepath.Join(rootDir, "win.txt"), original, 0o644); err != nil {
		t.Fatal(err)
	}
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	_, hash, err := w.ReadFile("win.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.WriteFileAtomic("grant1", "win.txt", []byte("line1\nline2\nline3\n"), hash, false); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(rootDir, "win.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, utf8BOM) {
		t.Error("BOM was not preserved")
	}
	body := data[len(utf8BOM):]
	if bytes.Contains(body, []byte("\n")) && !bytes.Contains(body, []byte("\r\n")) {
		t.Errorf("newlines were not converted to CRLF: %q", body)
	}
	if strings.Contains(strings.ReplaceAll(string(body), "\r\n", ""), "\n") {
		t.Errorf("mixed newlines after write: %q", body)
	}
	if !bytes.HasSuffix(body, []byte("line3\r\n")) {
		t.Errorf("body = %q", body)
	}
}

func TestWriteRejectsMixedNewlines(t *testing.T) {
	rootDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootDir, "mixed.txt"), []byte("a\nb\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()
	_, hash, err := w.ReadFile("mixed.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.WriteFileAtomic("grant1", "mixed.txt", []byte("replaced\n"), hash, false); !errors.Is(err, ws.ErrMixedNewlines) {
		t.Fatalf("error = %v, want ErrMixedNewlines", err)
	}
}

func TestSnapshotRetention(t *testing.T) {
	rootDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootDir, "a.txt"), []byte("v0"), 0o644); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	mgr := newTestManager(t, []ws.WorkspaceConfig{{
		Name: "app", Path: rootDir, MaxPerm: ws.PermWrite,
	}}, ws.ManagerOptions{DataDir: dataDir, MaxSnapshotsPerGrant: 2, RipgrepPath: "none"})
	defer mgr.Close()
	w, _ := mgr.Get("app")

	content := "v0"
	for i := 1; i <= 3; i++ {
		_, hash, err := w.ReadFile("a.txt")
		if err != nil {
			t.Fatal(err)
		}
		content = "v" + string(rune('0'+i))
		if _, _, err := w.WriteFileAtomic("grant1", "a.txt", []byte(content), hash, false); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	base := filepath.Join(dataDir, "snapshots", "grant1")
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry.Name())
		}
	}
	sort.Strings(dirs)
	if len(dirs) != 2 {
		t.Fatalf("snapshot dirs = %v, want 2", dirs)
	}
}

func TestWriteRejectsUnsafeInputs(t *testing.T) {
	rootDir := t.TempDir()
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	data := bytes.Repeat([]byte("a"), ws.MaxFileSize+1)
	if _, _, err := w.WriteFileAtomic("grant1", "big.txt", data, "", true); !errors.Is(err, ws.ErrFileTooLarge) {
		t.Errorf("big file error = %v, want ErrFileTooLarge", err)
	}
	for _, path := range []string{"../escape.txt", "/abs.txt", `C:\x.txt`, ".env", ".git/config"} {
		if _, _, err := w.WriteFileAtomic("grant1", path, []byte("x"), "", true); err == nil {
			t.Errorf("WriteFileAtomic(%q) succeeded, want error", path)
		}
	}
	if _, _, err := w.WriteFileAtomic("../grant", "ok.txt", []byte("x"), "", true); err == nil {
		t.Error("unsafe grant id accepted")
	}
}

func TestWriteRejectsSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows")
	}
	rootDir := t.TempDir()
	target := filepath.Join(rootDir, "target.txt")
	if err := os.WriteFile(target, []byte("target"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(rootDir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()

	if _, _, err := w.WriteFileAtomic("grant1", "link.txt", []byte("new"), "", true); err == nil {
		t.Fatal("WriteFileAtomic wrote through a symlink")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "target" {
		t.Fatalf("symlink target changed: %q, %v", data, err)
	}
}

func TestWriteRejectsCRLFExpansionOverLimit(t *testing.T) {
	rootDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootDir, "win.txt"), []byte("x\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr, w, _ := newSingleWorkspace(t, rootDir)
	defer mgr.Close()
	_, hash, err := w.ReadFile("win.txt")
	if err != nil {
		t.Fatal(err)
	}
	// 700k LF lines fit under 2 MiB, but converting them to CRLF exceeds it.
	data := bytes.Repeat([]byte("a\n"), 700_000)
	if len(data) > ws.MaxFileSize {
		t.Fatalf("test input already exceeds limit: %d", len(data))
	}
	if _, _, err := w.WriteFileAtomic("grant1", "win.txt", data, hash, false); !errors.Is(err, ws.ErrFileTooLarge) {
		t.Fatalf("error = %v, want ErrFileTooLarge", err)
	}
	unchanged, err := os.ReadFile(filepath.Join(rootDir, "win.txt"))
	if err != nil || string(unchanged) != "x\r\n" {
		t.Fatalf("file changed after rejected write: %q, %v", unchanged, err)
	}
}
