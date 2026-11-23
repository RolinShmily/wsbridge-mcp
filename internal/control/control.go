// Package control implements the local-only loopback control plane and active
// workspace persistence used by "wsbridge use" to hot-switch a running
// "wsbridge serve" instance without exposing control endpoints to the public tunnel.
package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	controlFileName         = "control.json"
	activeWorkspaceFileName = "active-workspace.json"
	maxControlBody          = 64 << 10
)

// ErrNotRunning indicates that no live wsbridge control server responded.
var ErrNotRunning = errors.New("wsbridge serve is not running")

// ActiveWorkspace is persisted in <data_dir>/active-workspace.json so a
// restarted background service restores the last selected project directory.
type ActiveWorkspace struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// WorkspaceInfo describes one workspace currently mounted by the server.
type WorkspaceInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	MaxPerm string `json:"max_perm"`
}

// Handlers supplies the server-side operations invoked over the control plane.
type Handlers struct {
	List   func() []WorkspaceInfo
	Switch func(path, name string) (WorkspaceInfo, error)
}

type controlFile struct {
	Addr  string `json:"addr"`
	Token string `json:"token"`
	PID   int    `json:"pid"`
}

// Server serves authenticated local-only workspace control requests on an
// ephemeral 127.0.0.1 port completely separate from the tunneled HTTP port.
type Server struct {
	dataDir  string
	token    string
	listener net.Listener
	httpSrv  *http.Server
	handlers Handlers
}

// Start binds an ephemeral loopback listener, writes <data_dir>/control.json
// with mode 0600, and begins serving control requests.
func Start(dataDir string, h Handlers) (*Server, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("control: data directory is required")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("control: create data directory: %w", err)
	}
	tokBytes := make([]byte, 32)
	if _, err := rand.Read(tokBytes); err != nil {
		return nil, fmt.Errorf("control: generate token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokBytes)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("control: listen on loopback: %w", err)
	}

	s := &Server{
		dataDir:  dataDir,
		token:    token,
		listener: ln,
		handlers: h,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/workspace", s.requireToken(s.handleGetWorkspace))
	mux.HandleFunc("POST /v1/workspace", s.requireToken(s.handleSwitchWorkspace))
	s.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	s.httpSrv.SetKeepAlivesEnabled(false)

	meta := controlFile{
		Addr:  ln.Addr().String(),
		Token: token,
		PID:   os.Getpid(),
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("control: encode metadata: %w", err)
	}
	if err := writeAtomic(filepath.Join(dataDir, controlFileName), raw); err != nil {
		_ = ln.Close()
		return nil, err
	}

	go func() {
		_ = s.httpSrv.Serve(ln)
	}()
	return s, nil
}

// Addr returns the bound loopback host:port.
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

// Close shuts down the control server and removes control.json.
func (s *Server) Close(ctx context.Context) error {
	_ = os.Remove(filepath.Join(s.dataDir, controlFileName))
	if ctx == nil {
		ctx = context.Background()
	}
	shutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err := s.httpSrv.Shutdown(shutCtx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) requireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		got := auth[len(prefix):]
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (s *Server) handleGetWorkspace(w http.ResponseWriter, _ *http.Request) {
	var list []WorkspaceInfo
	if s.handlers.List != nil {
		list = s.handlers.List()
	}
	if list == nil {
		list = []WorkspaceInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"workspaces": list})
}

func (s *Server) handleSwitchWorkspace(w http.ResponseWriter, r *http.Request) {
	if s.handlers.Switch == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "workspace switching is not supported"})
		return
	}
	var req struct {
		Path string `json:"path"`
		Name string `json:"name,omitempty"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxControlBody))
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	req.Path = strings.TrimSpace(req.Path)
	req.Name = strings.TrimSpace(req.Name)
	if req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path is required"})
		return
	}
	info, err := s.handlers.Switch(req.Path, req.Name)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"workspace": info})
}

// GetWorkspaces queries a running wsbridge serve instance for its active workspaces.
// Returns ErrNotRunning if no live instance is reachable.
func GetWorkspaces(ctx context.Context, dataDir string) ([]WorkspaceInfo, error) {
	meta, err := readControlFile(dataDir)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://"+meta.Addr+"/v1/workspace", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+meta.Token)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotRunning, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxControlBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, decodeError(resp.StatusCode, body)
	}
	var out struct {
		Workspaces []WorkspaceInfo `json:"workspaces"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("control: decode response: %w", err)
	}
	return out.Workspaces, nil
}

// SwitchWorkspace instructs a running wsbridge serve instance to switch its
// active workspace to path (with an optional name override). Returns
// ErrNotRunning if no live instance is reachable.
func SwitchWorkspace(ctx context.Context, dataDir, path, name string) (WorkspaceInfo, error) {
	meta, err := readControlFile(dataDir)
	if err != nil {
		return WorkspaceInfo{}, err
	}
	payload, err := json.Marshal(map[string]string{"path": path, "name": name})
	if err != nil {
		return WorkspaceInfo{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, "http://"+meta.Addr+"/v1/workspace", bytes.NewReader(payload))
	if err != nil {
		return WorkspaceInfo{}, err
	}
	req.Header.Set("Authorization", "Bearer "+meta.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return WorkspaceInfo{}, fmt.Errorf("%w: %v", ErrNotRunning, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxControlBody))
	if err != nil {
		return WorkspaceInfo{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return WorkspaceInfo{}, decodeError(resp.StatusCode, body)
	}
	var out struct {
		Workspace WorkspaceInfo `json:"workspace"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return WorkspaceInfo{}, fmt.Errorf("control: decode response: %w", err)
	}
	return out.Workspace, nil
}

// SaveActiveWorkspace persists the active workspace selection to
// <data_dir>/active-workspace.json with mode 0600.
func SaveActiveWorkspace(dataDir string, active ActiveWorkspace) error {
	if dataDir == "" {
		return fmt.Errorf("control: data directory is required")
	}
	raw, err := json.MarshalIndent(active, "", "  ")
	if err != nil {
		return fmt.Errorf("control: encode active workspace: %w", err)
	}
	raw = append(raw, '\n')
	return writeAtomic(filepath.Join(dataDir, activeWorkspaceFileName), raw)
}

// LoadActiveWorkspace reads <data_dir>/active-workspace.json.
func LoadActiveWorkspace(dataDir string) (ActiveWorkspace, error) {
	raw, err := os.ReadFile(filepath.Join(dataDir, activeWorkspaceFileName))
	if err != nil {
		return ActiveWorkspace{}, err
	}
	var out ActiveWorkspace
	if err := json.Unmarshal(raw, &out); err != nil {
		return ActiveWorkspace{}, fmt.Errorf("control: parse active workspace: %w", err)
	}
	out.Path = strings.TrimSpace(out.Path)
	out.Name = strings.TrimSpace(out.Name)
	if out.Path == "" {
		return ActiveWorkspace{}, os.ErrNotExist
	}
	return out, nil
}

func readControlFile(dataDir string) (controlFile, error) {
	raw, err := os.ReadFile(filepath.Join(dataDir, controlFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return controlFile{}, ErrNotRunning
		}
		return controlFile{}, err
	}
	var meta controlFile
	if err := json.Unmarshal(raw, &meta); err != nil || meta.Addr == "" || meta.Token == "" {
		return controlFile{}, ErrNotRunning
	}
	host, _, err := net.SplitHostPort(meta.Addr)
	if err != nil {
		return controlFile{}, ErrNotRunning
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return controlFile{}, fmt.Errorf("control: refusing non-loopback address %q", meta.Addr)
	}
	return meta, nil
}

func decodeError(status int, body []byte) error {
	var errResp struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
		return fmt.Errorf("%s", errResp.Error)
	}
	return fmt.Errorf("control server returned HTTP %d", status)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeAtomic(target string, data []byte) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("control: create directory %q: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".wsbridge-ctrl-*.tmp")
	if err != nil {
		return fmt.Errorf("control: create temp file: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("control: chmod temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("control: write temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("control: sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("control: close temp file: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("control: replace %q: %w", target, err)
	}
	return nil
}
