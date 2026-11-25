// Package oauth implements the built-in OAuth 2.1 authorization server.
package oauth

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/RolinShmily/wsbridge-mcp/internal/audit"
	"github.com/RolinShmily/wsbridge-mcp/internal/ws"
)

//go:embed consent.html
var consentHTML string

// WorkspaceChoice is one workspace offered on the consent page.
type WorkspaceChoice struct {
	Name    string
	Path    string
	MaxPerm ws.Permission
	Checks  []string
}

// Config configures the authorization server.
type Config struct {
	Issuer string
	Store  *Store
	Audit  *audit.Logger
	Logger *slog.Logger
	// AllowRedirectHosts extends the built-in redirect host allowlist.
	AllowRedirectHosts []string
	// Workspaces are the static workspaces displayed on the consent page when
	// WorkspacesProvider is nil.
	Workspaces []WorkspaceChoice
	// WorkspacesProvider dynamically returns the currently active workspace(s)
	// for display on the consent page (used with hot-switching via "wsbridge use").
	WorkspacesProvider func() []WorkspaceChoice
	// LocalMaxPerm is the optional local server permission ceiling shown as a
	// hint on the consent page. Defaults to ws.PermCheck (full access).
	LocalMaxPerm ws.Permission
	// Now overrides the clock in tests.
	Now func() time.Time
	// Argon2 is used by "wsbridge passwd"; verification reads parameters from
	// the stored hash.
	Argon2 Argon2Params
}

// Server serves OAuth discovery, registration, authorization, token, and
// revocation endpoints.
type Server struct {
	issuer             string
	resourceURL        string
	store              *Store
	audit              *audit.Logger
	logger             *slog.Logger
	now                func() time.Time
	argon2             Argon2Params
	redirects          map[string]bool
	workspaces         []WorkspaceChoice
	workspacesProvider func() []WorkspaceChoice
	localMaxPerm       ws.Permission

	codes    *codeStore
	requests *authRequestStore
	lockout  *lockout

	consent *template.Template
	error   *template.Template
}

// New validates cfg and builds a Server.
func New(cfg Config) (*Server, error) {
	issuer := strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	if issuer == "" {
		return nil, fmt.Errorf("oauth: issuer is required")
	}
	u, err := url.Parse(issuer)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("oauth: issuer must be an absolute URL without a path")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("oauth: store is required")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	consent, err := template.New("consent").Parse(consentHTML)
	if err != nil {
		return nil, fmt.Errorf("oauth: parse consent template: %w", err)
	}
	errorTmpl, err := template.New("authorize_error").Parse(authorizeErrorHTML)
	if err != nil {
		return nil, fmt.Errorf("oauth: parse error template: %w", err)
	}
	argon := cfg.Argon2
	if argon == (Argon2Params{}) {
		argon = DefaultArgon2Params
	}
	localMaxPerm := cfg.LocalMaxPerm
	if localMaxPerm == ws.PermNone {
		localMaxPerm = ws.PermCheck
	}
	return &Server{
		issuer:             issuer,
		resourceURL:        issuer + "/mcp",
		store:              cfg.Store,
		audit:              cfg.Audit,
		logger:             logger,
		now:                now,
		argon2:             argon,
		redirects:          RedirectHostAllowlist(cfg.AllowRedirectHosts),
		workspaces:         append([]WorkspaceChoice(nil), cfg.Workspaces...),
		workspacesProvider: cfg.WorkspacesProvider,
		localMaxPerm:       localMaxPerm,
		codes:              newCodeStore(now),
		requests:           newAuthRequestStore(now),
		lockout:            newLockout(now),
		consent:            consent,
		error:              errorTmpl,
	}, nil
}

func (s *Server) currentWorkspaces() []WorkspaceChoice {
	if s.workspacesProvider != nil {
		return s.workspacesProvider()
	}
	return s.workspaces
}

// Issuer returns the configured issuer.
func (s *Server) Issuer() string { return s.issuer }

// ResourceURL returns the protected MCP resource identifier.
func (s *Server) ResourceURL() string { return s.resourceURL }

// ResourceMetadataURL returns the RFC 9728 metadata URL for WWW-Authenticate.
func (s *Server) ResourceMetadataURL() string {
	return s.issuer + "/.well-known/oauth-protected-resource/mcp"
}

// Mount registers all OAuth routes. Every path is exact; no route relies on
// http.ServeMux subtree redirection.
func (s *Server) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.handleProtectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", s.handleProtectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleAuthorizationServerMetadata)
	mux.HandleFunc("POST /oauth/register", s.handleRegister)
	mux.HandleFunc("GET /oauth/authorize", s.handleAuthorizeGet)
	mux.HandleFunc("POST /oauth/authorize", s.handleAuthorizePost)
	mux.HandleFunc("POST /oauth/token", s.handleToken)
	mux.HandleFunc("POST /oauth/revoke", s.handleRevoke)
}

// Handler returns a mux with only the OAuth routes (tests and doctor use it).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.Mount(mux)
	return mux
}

func (s *Server) setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, value any) {
	s.setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	s.writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func (s *Server) auditEvent(event string, fields map[string]any) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Log(event, fields); err != nil {
		s.logger.Warn("audit write failed", "event", event, "error", err)
	}
}
