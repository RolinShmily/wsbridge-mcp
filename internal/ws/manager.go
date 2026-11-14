package ws

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	// MaxFileSize is the read/write limit for a single file (2 MiB).
	MaxFileSize = 2 << 20
	// MaxCheckOutput is the maximum captured output of a run_check command.
	MaxCheckOutput = 64 << 10
)

// Sentinel errors returned by workspace operations.
var (
	ErrInvalidPath        = errors.New("invalid workspace path")
	ErrDeniedPath         = errors.New("path blocked by sensitive-file policy")
	ErrFileTooLarge       = errors.New("file exceeds 2 MiB limit")
	ErrNotRegularFile     = errors.New("not a regular file")
	ErrChecksumMismatch   = errors.New("sha256 mismatch")
	ErrMissingChecksum    = errors.New("expected sha256 is required to overwrite an existing file")
	ErrChecksumForMissing = errors.New("expected sha256 was provided but the file does not exist")
	ErrFileExists         = errors.New("file already exists")
	ErrMixedNewlines      = errors.New("file has mixed line endings")
	ErrUnknownCheck       = errors.New("unknown check")
	ErrCheckNotAllowed    = errors.New("check is not allowed for this workspace")
)

// WorkspaceConfig describes one workspace supplied by the configuration layer.
type WorkspaceConfig struct {
	Name    string
	Path    string
	MaxPerm Permission
	Checks  []string
}

// ManagerOptions configures the workspace pool.
type ManagerOptions struct {
	DataDir              string
	MaxSnapshotsPerGrant int
	DenyPatterns         []string
	// RipgrepPath selects the ripgrep executable. Empty means auto-detect on
	// PATH; "none" disables ripgrep and forces the pure-Go search fallback.
	RipgrepPath string
}

// Manager owns one *os.Root per configured workspace.
type Manager struct {
	workspaces map[string]*Workspace
	order      []string
}

// Workspace provides sandboxed file operations within a single directory.
type Workspace struct {
	name         string
	hostPath     string
	maxPerm      Permission
	checks       []string
	root         *os.Root
	denyPatterns []string
	dataDir      string
	maxSnapshots int
	ripgrepPath  string
}

var workspaceNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// NewManager opens every configured workspace root.
func NewManager(configs []WorkspaceConfig, opts ManagerOptions) (*Manager, error) {
	if opts.DataDir == "" {
		return nil, fmt.Errorf("ws: data directory is required")
	}
	dataDir, err := filepath.Abs(opts.DataDir)
	if err != nil {
		return nil, fmt.Errorf("ws: resolve data directory: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("ws: create data directory: %w", err)
	}
	if opts.MaxSnapshotsPerGrant <= 0 {
		opts.MaxSnapshotsPerGrant = 20
	}

	denyPatterns := append([]string(nil), defaultDenyPatterns...)
	denyPatterns = append(denyPatterns, opts.DenyPatterns...)

	ripgrepPath := opts.RipgrepPath
	switch ripgrepPath {
	case "none":
		ripgrepPath = ""
	case "":
		if found, err := exec.LookPath("rg"); err == nil {
			ripgrepPath = found
		}
	}

	m := &Manager{workspaces: make(map[string]*Workspace, len(configs))}
	closeOpened := func() {
		for _, name := range m.order {
			_ = m.workspaces[name].root.Close()
		}
	}
	for _, cfg := range configs {
		if cfg.Name == "" || cfg.Name == "." || cfg.Name == ".." || !workspaceNameRE.MatchString(cfg.Name) {
			closeOpened()
			return nil, fmt.Errorf("ws: invalid workspace name %q", cfg.Name)
		}
		if _, exists := m.workspaces[cfg.Name]; exists {
			closeOpened()
			return nil, fmt.Errorf("ws: duplicate workspace name %q", cfg.Name)
		}
		if cfg.MaxPerm < PermRead || cfg.MaxPerm > PermCheck {
			closeOpened()
			return nil, fmt.Errorf("ws: workspace %q has invalid permission %d", cfg.Name, cfg.MaxPerm)
		}
		for _, check := range cfg.Checks {
			if _, ok := builtinChecks[check]; !ok {
				closeOpened()
				return nil, fmt.Errorf("ws: workspace %q: unknown check %q", cfg.Name, check)
			}
		}
		root, err := os.OpenRoot(cfg.Path)
		if err != nil {
			closeOpened()
			return nil, fmt.Errorf("ws: open workspace %q at %q: %w", cfg.Name, cfg.Path, err)
		}
		m.workspaces[cfg.Name] = &Workspace{
			name:         cfg.Name,
			hostPath:     cfg.Path,
			maxPerm:      cfg.MaxPerm,
			checks:       append([]string(nil), cfg.Checks...),
			root:         root,
			denyPatterns: denyPatterns,
			dataDir:      dataDir,
			maxSnapshots: opts.MaxSnapshotsPerGrant,
			ripgrepPath:  ripgrepPath,
		}
		m.order = append(m.order, cfg.Name)
	}
	return m, nil
}

// Get returns a workspace by name.
func (m *Manager) Get(name string) (*Workspace, bool) {
	w, ok := m.workspaces[name]
	return w, ok
}

// Names returns workspace names in configuration order.
func (m *Manager) Names() []string {
	return append([]string(nil), m.order...)
}

// Workspaces returns all workspaces in configuration order.
func (m *Manager) Workspaces() []*Workspace {
	out := make([]*Workspace, 0, len(m.order))
	for _, name := range m.order {
		out = append(out, m.workspaces[name])
	}
	return out
}

// Close closes all workspace roots.
func (m *Manager) Close() error {
	var errs []error
	for _, name := range m.order {
		if err := m.workspaces[name].root.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Name returns the configured workspace name.
func (w *Workspace) Name() string { return w.name }

// MaxPerm returns the configured maximum permission.
func (w *Workspace) MaxPerm() Permission { return w.maxPerm }

// AllowedChecks returns a copy of the configured check whitelist.
func (w *Workspace) AllowedChecks() []string {
	return append([]string(nil), w.checks...)
}

// IsDenied reports whether rel matches this workspace's sensitive-file policy.
func (w *Workspace) IsDenied(rel string) bool {
	return matchesDeny(w.denyPatterns, rel)
}

func (w *Workspace) clean(raw string) (string, error) {
	rel, err := SanitizeRelPath(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidPath, err)
	}
	if w.IsDenied(rel) {
		return "", fmt.Errorf("%w: %s", ErrDeniedPath, rel)
	}
	if err := w.ensureNoSymlinkPrefix(rel); err != nil {
		return "", err
	}
	return rel, nil
}

// ensureNoSymlinkPrefix rejects existing symbolic links in the directory
// components leading to rel. os.Root resolves symlinks that stay inside the
// root, so a lexical denylist check alone would let a workspace link such as
// leaks -> .git expose sensitive files (or write into .git/hooks). Components
// that do not exist yet are accepted so writes can create them.
func (w *Workspace) ensureNoSymlinkPrefix(rel string) error {
	if rel == "." {
		return nil
	}
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		prefix := strings.Join(parts[:i], "/")
		info, err := w.root.Lstat(prefix)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("%w: inspect %q: %v", ErrInvalidPath, prefix, err)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: path component %q is a symbolic link", ErrDeniedPath, prefix)
		}
		if !info.IsDir() {
			return fmt.Errorf("%w: path component %q is not a directory", ErrInvalidPath, prefix)
		}
	}
	return nil
}

// StatFile returns lstat information for a sandboxed relative path.
func (w *Workspace) StatFile(relPath string) (fs.FileInfo, error) {
	rel, err := w.clean(relPath)
	if err != nil {
		return nil, err
	}
	return w.root.Lstat(rel)
}

// ReadFile reads a regular file (maximum 2 MiB) and returns its SHA-256 hex.
func (w *Workspace) ReadFile(relPath string) ([]byte, string, error) {
	rel, err := w.clean(relPath)
	if err != nil {
		return nil, "", err
	}
	info, err := w.root.Lstat(rel)
	if err != nil {
		return nil, "", err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, "", fmt.Errorf("%w: symbolic links are not readable", ErrNotRegularFile)
	}
	if !info.Mode().IsRegular() {
		return nil, "", ErrNotRegularFile
	}
	if info.Size() > MaxFileSize {
		return nil, "", ErrFileTooLarge
	}
	// Narrow the window between clean's symlink check and the actual open.
	if err := w.ensureNoSymlinkPrefix(rel); err != nil {
		return nil, "", err
	}
	data, err := w.root.ReadFile(rel)
	if err != nil {
		return nil, "", err
	}
	return data, hashBytes(data), nil
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func truncateCheckOutput(s string) string {
	if len(s) <= MaxCheckOutput {
		return s
	}
	cut := MaxCheckOutput
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "\n[output truncated at 64KB]\n"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// sanitizeName keeps snapshot path components from escaping the data dir.
func sanitizeName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("ws: empty name")
	}
	if strings.ContainsAny(name, `/\`) || name == "." || name == ".." || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("ws: unsafe name %q", name)
	}
	return name, nil
}
