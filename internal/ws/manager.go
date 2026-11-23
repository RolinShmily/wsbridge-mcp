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
	"sync"
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
	ErrWorkspaceClosed    = errors.New("workspace is no longer active")
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

// Manager owns one *os.Root per active workspace and supports concurrency-safe
// hot-switching of the active workspace.
type Manager struct {
	mu           sync.RWMutex
	workspaces   map[string]*Workspace
	order        []string
	dataDir      string
	maxSnapshots int
	denyPatterns []string
	ripgrepPath  string
	closing      sync.WaitGroup
}

// Workspace provides sandboxed file operations within a single directory.
type Workspace struct {
	name         string
	hostPath     string
	maxPerm      Permission
	checks       []string
	rootMu       sync.RWMutex
	root         *os.Root
	closed       bool
	denyPatterns []string
	dataDir      string
	maxSnapshots int
	ripgrepPath  string
}

var workspaceNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// DeriveWorkspaceName converts a directory path's basename into a valid
// workspace name matching [A-Za-z0-9._-]+, falling back to "workspace".
func DeriveWorkspaceName(dir string) string {
	trimmed := strings.TrimSpace(dir)
	if trimmed == "" {
		return "workspace"
	}
	base := filepath.Base(filepath.Clean(trimmed))
	if base == "" || base == "." || base == ".." || base == string(filepath.Separator) {
		return "workspace"
	}
	var b strings.Builder
	prevDash := false
	for _, r := range base {
		valid := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-'
		if valid {
			if r == '-' && prevDash {
				continue
			}
			b.WriteRune(r)
			prevDash = r == '-'
		} else if b.Len() > 0 && !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	name := strings.Trim(b.String(), ".-")
	if name == "" || name == "." || name == ".." || !workspaceNameRE.MatchString(name) {
		return "workspace"
	}
	return name
}

// NewManager opens every configured workspace root. An empty configs slice is
// valid when starting in dynamic mode before an active workspace is selected.
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

	m := &Manager{
		workspaces:   make(map[string]*Workspace, len(configs)),
		dataDir:      dataDir,
		maxSnapshots: opts.MaxSnapshotsPerGrant,
		denyPatterns: denyPatterns,
		ripgrepPath:  ripgrepPath,
	}
	closeOpened := func() {
		for _, name := range m.order {
			_ = m.workspaces[name].closeRoot()
		}
	}
	for _, cfg := range configs {
		w, err := m.openWorkspace(cfg)
		if err != nil {
			closeOpened()
			return nil, err
		}
		if _, exists := m.workspaces[w.name]; exists {
			_ = w.closeRoot()
			closeOpened()
			return nil, fmt.Errorf("ws: duplicate workspace name %q", w.name)
		}
		m.workspaces[w.name] = w
		m.order = append(m.order, w.name)
	}
	return m, nil
}

func (m *Manager) openWorkspace(cfg WorkspaceConfig) (*Workspace, error) {
	if cfg.Name == "" || cfg.Name == "." || cfg.Name == ".." || !workspaceNameRE.MatchString(cfg.Name) {
		return nil, fmt.Errorf("ws: invalid workspace name %q", cfg.Name)
	}
	if cfg.MaxPerm < PermRead || cfg.MaxPerm > PermCheck {
		return nil, fmt.Errorf("ws: workspace %q has invalid permission %d", cfg.Name, cfg.MaxPerm)
	}
	for _, check := range cfg.Checks {
		if _, ok := builtinChecks[check]; !ok {
			return nil, fmt.Errorf("ws: workspace %q: unknown check %q", cfg.Name, check)
		}
	}
	absPath, err := filepath.Abs(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("ws: resolve workspace %q path %q: %w", cfg.Name, cfg.Path, err)
	}
	root, err := os.OpenRoot(absPath)
	if err != nil {
		return nil, fmt.Errorf("ws: open workspace %q at %q: %w", cfg.Name, absPath, err)
	}
	return &Workspace{
		name:         cfg.Name,
		hostPath:     absPath,
		maxPerm:      cfg.MaxPerm,
		checks:       append([]string(nil), cfg.Checks...),
		root:         root,
		denyPatterns: m.denyPatterns,
		dataDir:      m.dataDir,
		maxSnapshots: m.maxSnapshots,
		ripgrepPath:  m.ripgrepPath,
	}, nil
}

// SetActive atomically replaces the manager's active workspace with cfg.
// If opening cfg fails, the previously active workspace(s) remain untouched.
func (m *Manager) SetActive(cfg WorkspaceConfig) (*Workspace, error) {
	w, err := m.openWorkspace(cfg)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	old := make([]*Workspace, 0, len(m.order))
	for _, name := range m.order {
		old = append(old, m.workspaces[name])
	}
	m.workspaces = map[string]*Workspace{w.name: w}
	m.order = []string{w.name}
	m.mu.Unlock()

	if len(old) > 0 {
		m.closing.Add(1)
		go func() {
			defer m.closing.Done()
			for _, prev := range old {
				_ = prev.closeRoot()
			}
		}()
	}
	return w, nil
}

// Get returns a workspace by name.
func (m *Manager) Get(name string) (*Workspace, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	w, ok := m.workspaces[name]
	return w, ok
}

// Names returns workspace names in configuration order.
func (m *Manager) Names() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string(nil), m.order...)
}

// Workspaces returns all workspaces in configuration order.
func (m *Manager) Workspaces() []*Workspace {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Workspace, 0, len(m.order))
	for _, name := range m.order {
		out = append(out, m.workspaces[name])
	}
	return out
}

// Close closes all active workspace roots and waits for any deferred closures
// from prior hot-switches to complete.
func (m *Manager) Close() error {
	m.mu.Lock()
	active := make([]*Workspace, 0, len(m.order))
	for _, name := range m.order {
		active = append(active, m.workspaces[name])
	}
	m.workspaces = nil
	m.order = nil
	m.mu.Unlock()

	var errs []error
	for _, w := range active {
		if err := w.closeRoot(); err != nil {
			errs = append(errs, err)
		}
	}
	m.closing.Wait()
	return errors.Join(errs...)
}

func (w *Workspace) closeRoot() error {
	w.rootMu.Lock()
	defer w.rootMu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.root == nil {
		return nil
	}
	return w.root.Close()
}

// Name returns the configured workspace name.
func (w *Workspace) Name() string { return w.name }

// HostPath returns the absolute host directory path for this workspace.
func (w *Workspace) HostPath() string { return w.hostPath }

// MaxPerm returns the configured maximum permission.
func (w *Workspace) MaxPerm() Permission { return w.maxPerm }

// AllowedChecks returns the check identifiers permitted for this workspace.
// When no explicit subset was configured, all built-in checks are returned.
func (w *Workspace) AllowedChecks() []string {
	if len(w.checks) == 0 {
		return BuiltinCheckNames()
	}
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
	w.rootMu.RLock()
	defer w.rootMu.RUnlock()
	if w.closed {
		return nil, ErrWorkspaceClosed
	}
	rel, err := w.clean(relPath)
	if err != nil {
		return nil, err
	}
	return w.root.Lstat(rel)
}

// ReadFile reads a regular file (maximum 2 MiB) and returns its SHA-256 hex.
func (w *Workspace) ReadFile(relPath string) ([]byte, string, error) {
	w.rootMu.RLock()
	defer w.rootMu.RUnlock()
	if w.closed {
		return nil, "", ErrWorkspaceClosed
	}
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
