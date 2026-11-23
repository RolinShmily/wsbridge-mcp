// Package mcpsrv mounts the wsbridge MCP tool set on the Streamable HTTP
// transport at both /mcp and /mcp/.
package mcpsrv

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"wsbridge/internal/audit"
	"wsbridge/internal/tools"
	"wsbridge/internal/ws"
)

// DefaultInstructions are advertised to MCP clients during initialization.
const DefaultInstructions = "wsbridge exposes sandboxed tools for the active local workspace on the host. " +
	"The active workspace can switch dynamically when the user changes directories locally; call list_workspaces to confirm the current workspace name and available checks. " +
	"All paths are relative to the selected workspace. Sensitive files are blocked, and writes require the current SHA-256 when replacing an existing file."

// Options configures the MCP server.
type Options struct {
	Manager *ws.Manager
	// GrantID is the audit/snapshot identity used by the built-in development
	// scope. It is not used when Scope is supplied.
	GrantID      string
	Version      string
	Instructions string
	Logger       *slog.Logger
	// Scope overrides the manager-based development scope. M2 supplies a
	// per-request OAuth grant scope here.
	Scope tools.ScopeFunc
	// Auth enables mandatory bearer authentication. Nil is only for focused
	// transport tests; the CLI always supplies it.
	Auth *AuthConfig
	// Audit receives tool_call records.
	Audit *audit.Logger
}

// Server owns an MCP server and its HTTP transport handler.
type Server struct {
	handler http.Handler
	mcp     *mcp.Server
}

// New builds the MCP server and registers the seven tools.
func New(opts Options) (*Server, error) {
	if opts.Scope == nil && opts.Manager == nil {
		return nil, fmt.Errorf("mcpsrv: a workspace manager or explicit scope is required")
	}
	version := opts.Version
	if version == "" {
		version = "dev"
	}
	instructions := opts.Instructions
	if instructions == "" {
		instructions = DefaultInstructions
	}
	scope := opts.Scope
	if scope == nil {
		mgr := opts.Manager
		grantID := opts.GrantID
		if grantID == "" {
			grantID = "dev"
		}
		scope = func(context.Context) (*tools.Scope, error) {
			s := &tools.Scope{GrantID: grantID}
			for _, w := range mgr.Workspaces() {
				s.Allowed = append(s.Allowed, tools.Access{Workspace: w, Permission: w.MaxPerm()})
			}
			return s, nil
		}
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "wsbridge",
		Title:   "wsbridge local workspace bridge",
		Version: version,
	}, &mcp.ServerOptions{
		Instructions: instructions,
		Logger:       opts.Logger,
	})
	tools.Register(server, scope)
	if opts.Audit != nil {
		server.AddReceivingMiddleware(auditMiddleware(opts.Audit, opts.Logger))
	}

	var handler http.Handler = mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{
			// Access control is enforced by OAuth on the outer handler; the
			// SDK's Host-header check would also reject legitimate reverse
			// proxy hostnames.
			DisableLocalhostProtection: true,
			Stateless:                  true,
		})
	if opts.Auth != nil {
		authCfg := *opts.Auth
		if authCfg.Verifier == nil || authCfg.ResourceURL == "" || authCfg.ResourceMetadataURL == "" {
			return nil, fmt.Errorf("mcpsrv: Auth requires a verifier, resource URL, and metadata URL")
		}
		handler = requireBearer(handler, authCfg)
	}
	return &Server{handler: handler, mcp: server}, nil
}

// Handler returns the Streamable HTTP handler for /mcp and /mcp/.
func (s *Server) Handler() http.Handler { return s.handler }

// MCPServer exposes the underlying SDK server (used by tests and tooling).
func (s *Server) MCPServer() *mcp.Server { return s.mcp }

// Mount registers /mcp and /mcp/ explicitly so ServeMux never emits a 301
// redirect that would cause clients to drop the Authorization header.
func (s *Server) Mount(mux *http.ServeMux) {
	mux.Handle("/mcp", s.handler)
	mux.Handle("/mcp/", s.handler)
}
