package ws

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// WriteFileAtomic writes data to relPath inside the workspace. Existing files
// must supply expectSHA256 and are snapshotted first. createOnly forbids
// replacing an existing file. The return values are the new SHA-256 and the
// snapshot path (relative to <data_dir>/snapshots), if a snapshot was made.
func (w *Workspace) WriteFileAtomic(grantID, relPath string, data []byte, expectSHA256 string, createOnly bool) (string, string, error) {
	if _, err := sanitizeName(grantID); err != nil {
		return "", "", err
	}
	rel, err := w.clean(relPath)
	if err != nil {
		return "", "", err
	}
	if len(data) > MaxFileSize {
		return "", "", ErrFileTooLarge
	}
	expectSHA256 = strings.TrimSpace(expectSHA256)

	info, statErr := w.root.Lstat(rel)
	exists := statErr == nil
	existingHash := ""
	var snapshotRel string
	if exists {
		if !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 {
			return "", "", fmt.Errorf("%w: %s", ErrNotRegularFile, rel)
		}
		if createOnly {
			return "", "", fmt.Errorf("%w: %s", ErrFileExists, rel)
		}
		if expectSHA256 == "" {
			return "", "", fmt.Errorf("%w: %s", ErrMissingChecksum, rel)
		}
		if info.Size() > MaxFileSize {
			return "", "", ErrFileTooLarge
		}
		existing, err := w.root.ReadFile(rel)
		if err != nil {
			return "", "", err
		}
		actual := hashBytes(existing)
		if !strings.EqualFold(expectSHA256, actual) {
			return "", "", fmt.Errorf("%w (expected %s, actual %s)", ErrChecksumMismatch, expectSHA256, actual)
		}
		existingHash = actual
		crlf, lf := countNewlines(existing)
		if crlf > 0 && lf > 0 {
			return "", "", fmt.Errorf("%w: %s", ErrMixedNewlines, rel)
		}

		payload := preserveBOM(data, bytes.HasPrefix(existing, utf8BOM))
		switch {
		case crlf > 0:
			payload = toCRLF(payload)
		case lf > 0:
			payload = toLF(payload)
		}
		data = payload
		if len(data) > MaxFileSize {
			return "", "", ErrFileTooLarge
		}

		mode := info.Mode().Perm()
		if mode == 0 {
			mode = 0o644
		}
		snapshotRel, err = w.createSnapshot(grantID, rel, existing, mode)
		if err != nil {
			return "", "", err
		}
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return "", "", statErr
	} else if expectSHA256 != "" {
		return "", "", fmt.Errorf("%w: %s", ErrChecksumForMissing, rel)
	}

	dir := path.Dir(rel)
	if dir != "." {
		if err := w.root.MkdirAll(dir, 0o755); err != nil {
			return "", "", fmt.Errorf("create parent directory: %w", err)
		}
		// MkdirAll follows in-root symlinks; re-check after creating the
		// parents so a link swapped in after clean cannot redirect the write.
		if err := w.ensureNoSymlinkPrefix(rel); err != nil {
			return "", "", err
		}
	}
	suffix, err := randomHex(8)
	if err != nil {
		return "", "", err
	}
	tmpName := path.Join(dir, ".wsbridge-tmp-"+suffix)

	f, err := w.root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", "", fmt.Errorf("create temporary file: %w", err)
	}
	// A symlink swapped into the parent path since the previous check would
	// have redirected this temp file into a denied directory. Refuse before
	// writing any content.
	if err := w.ensureNoSymlinkPrefix(rel); err != nil {
		_ = f.Close()
		_ = w.root.Remove(tmpName)
		return "", "", err
	}
	cleanup := func() {
		_ = f.Close()
		_ = w.root.Remove(tmpName)
	}
	if _, err := f.Write(data); err != nil {
		cleanup()
		return "", "", fmt.Errorf("write temporary file: %w", err)
	}
	mode := fs.FileMode(0o644)
	if exists {
		mode = info.Mode().Perm()
		if mode == 0 {
			mode = 0o644
		}
	}
	if err := f.Chmod(mode); err != nil {
		cleanup()
		return "", "", fmt.Errorf("chmod temporary file: %w", err)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return "", "", fmt.Errorf("sync temporary file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = w.root.Remove(tmpName)
		return "", "", fmt.Errorf("close temporary file: %w", err)
	}
	// Re-validate immediately before Rename to narrow the TOCTOU window: a
	// concurrent writer must not be overwritten silently, and a file created
	// after the initial Lstat must not be clobbered by a create-only write.
	if exists {
		current, readErr := w.root.ReadFile(rel)
		if readErr != nil || hashBytes(current) != existingHash {
			_ = w.root.Remove(tmpName)
			return "", "", fmt.Errorf("%w: %s changed while writing", ErrChecksumMismatch, rel)
		}
	} else if _, statErr := w.root.Lstat(rel); statErr == nil {
		_ = w.root.Remove(tmpName)
		return "", "", fmt.Errorf("%w: %s", ErrFileExists, rel)
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		_ = w.root.Remove(tmpName)
		return "", "", statErr
	}
	if err := w.ensureNoSymlinkPrefix(rel); err != nil {
		_ = w.root.Remove(tmpName)
		return "", "", err
	}
	if err := w.root.Rename(tmpName, rel); err != nil {
		_ = w.root.Remove(tmpName)
		return "", "", fmt.Errorf("atomic rename: %w", err)
	}
	return hashBytes(data), snapshotRel, nil
}

func preserveBOM(data []byte, hadBOM bool) []byte {
	if !hadBOM {
		return data
	}
	if bytes.HasPrefix(data, utf8BOM) {
		return data
	}
	out := make([]byte, 0, len(utf8BOM)+len(data))
	out = append(out, utf8BOM...)
	return append(out, data...)
}

func countNewlines(data []byte) (crlf, lf int) {
	for i := 0; i < len(data); i++ {
		if data[i] != '\n' {
			continue
		}
		if i > 0 && data[i-1] == '\r' {
			crlf++
		} else {
			lf++
		}
	}
	return crlf, lf
}

func toCRLF(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
}

func toLF(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
}

func (w *Workspace) createSnapshot(grantID, rel string, data []byte, mode fs.FileMode) (string, error) {
	base := filepath.Join(w.dataDir, "snapshots", grantID)
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", fmt.Errorf("create snapshot directory: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102-150405.000")
	dir := filepath.Join(base, stamp)
	if _, err := os.Stat(dir); err == nil {
		suffix, err := randomHex(4)
		if err != nil {
			return "", err
		}
		dir = filepath.Join(base, stamp+"-"+suffix)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create snapshot directory: %w", err)
	}
	dest := filepath.Join(dir, w.name, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return "", fmt.Errorf("create snapshot parent: %w", err)
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create snapshot file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(dest)
		return "", fmt.Errorf("write snapshot: %w", err)
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		_ = os.Remove(dest)
		return "", fmt.Errorf("chmod snapshot: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(dest)
		return "", fmt.Errorf("sync snapshot: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(dest)
		return "", fmt.Errorf("close snapshot: %w", err)
	}
	w.pruneSnapshots(base)
	return path.Join(grantID, filepath.Base(dir), w.name, rel), nil
}

func (w *Workspace) pruneSnapshots(base string) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry.Name())
		}
	}
	if len(dirs) <= w.maxSnapshots {
		return
	}
	sort.Strings(dirs)
	for _, name := range dirs[:len(dirs)-w.maxSnapshots] {
		_ = os.RemoveAll(filepath.Join(base, name))
	}
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random suffix: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
