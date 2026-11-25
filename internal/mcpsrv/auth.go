package mcpsrv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/RolinShmily/wsbridge-mcp/internal/audit"
	"github.com/RolinShmily/wsbridge-mcp/internal/oauth"
	"github.com/RolinShmily/wsbridge-mcp/internal/tools"
	"github.com/RolinShmily/wsbridge-mcp/internal/ws"
)

// principalExtraKey is the TokenInfo.Extra key carrying the full grant.
const principalExtraKey = "wsbridge.grant_principal"

// AuthConfig turns on mandatory bearer-token authentication for the MCP
// transport. A nil AuthConfig leaves the handler unauthenticated and exists
// only for focused transport tests; the CLI always supplies one.
type AuthConfig struct {
	Verifier            oauth.TokenVerifier
	ResourceURL         string
	ResourceMetadataURL string
}

// GrantScope derives the per-call tool scope from the authenticated grant. It
// requires a bearer token, so a tool call can never inherit another grant's
// workspaces even if an MCP session is reused.
func GrantScope(manager *ws.Manager) tools.ScopeFunc {
	return func(ctx context.Context) (*tools.Scope, error) {
		info := auth.TokenInfoFromContext(ctx)
		if info == nil {
			return nil, errors.New("tool call is not authenticated")
		}
		principal, ok := info.Extra[principalExtraKey].(*oauth.GrantPrincipal)
		if !ok || principal == nil {
			return nil, errors.New("tool call has no grant principal")
		}
		scope := &tools.Scope{GrantID: principal.GrantID}
		if wildcardPerm, ok := principal.Workspaces[oauth.WildcardWorkspace]; ok {
			for _, w := range manager.Workspaces() {
				perm := ws.MinPermission(wildcardPerm, w.MaxPerm())
				scope.Allowed = append(scope.Allowed, tools.Access{Workspace: w, Permission: perm})
			}
			if len(scope.Allowed) == 0 {
				return nil, errors.New(`no active workspace is selected; run "wsbridge use <dir>" on the host`)
			}
			return scope, nil
		}
		list := make([]string, 0, len(principal.Workspaces))
		for name := range principal.Workspaces {
			list = append(list, name)
		}
		sort.Strings(list)
		for _, name := range list {
			w, ok := manager.Get(name)
			if !ok {
				// The workspace was removed from the config after the grant was
				// issued; it silently ceases to be accessible.
				continue
			}
			perm := ws.MinPermission(principal.Workspaces[name], w.MaxPerm())
			scope.Allowed = append(scope.Allowed, tools.Access{Workspace: w, Permission: perm})
		}
		if len(scope.Allowed) == 0 {
			return nil, errors.New("none of the grant's workspaces are configured on this server")
		}
		return scope, nil
	}
}

// requireBearer enforces the RFC 9728 discovery flow and rewrites the SDK's
// plain-text 401 into the JSON error body required by the endpoint spec.
func requireBearer(next http.Handler, cfg AuthConfig) http.Handler {
	verifier := func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		principal, err := cfg.Verifier.VerifyAccessToken(token, cfg.ResourceURL)
		if err != nil {
			// Never surface which check failed.
			return nil, fmt.Errorf("%w: missing or invalid bearer token", auth.ErrInvalidToken)
		}
		return &auth.TokenInfo{
			Scopes:     principal.Scopes,
			Expiration: principal.ExpiresAt,
			UserID:     principal.GrantID,
			Extra:      map[string]any{principalExtraKey: principal},
		}, nil
	}
	middleware := auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: cfg.ResourceMetadataURL,
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled := false
		writer := &authErrorWriter{ResponseWriter: w, innerCalled: &innerCalled}
		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			innerCalled = true
			next.ServeHTTP(w, r)
		})).ServeHTTP(writer, r)
	})
}

// authErrorWriter replaces the authentication middleware's 401 response with
// the OAuth JSON body while leaving responses from the MCP handler untouched.
type authErrorWriter struct {
	http.ResponseWriter
	innerCalled *bool
	wrote       bool
	suppress    bool
}

func (w *authErrorWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	if !*w.innerCalled && code == http.StatusUnauthorized {
		w.suppress = true
		h := w.Header()
		h.Set("Content-Type", "application/json; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		h.Del("Content-Length")
		w.ResponseWriter.WriteHeader(code)
		_, _ = io.WriteString(w.ResponseWriter, `{"error":"invalid_token","error_description":"missing or invalid bearer token"}`)
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *authErrorWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.suppress {
		return len(p), nil
	}
	return w.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach Flush/Hijack/Deadline for SSE.
func (w *authErrorWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// auditMiddleware records one tool_call audit record per tools/call attempt.
func auditMiddleware(logger *audit.Logger, srvLogger *slog.Logger) mcp.Middleware {
	if srvLogger == nil {
		srvLogger = slog.Default()
	}
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if logger == nil || method != "tools/call" {
				return next(ctx, method, req)
			}
			start := time.Now()
			result, err := next(ctx, method, req)
			fields := map[string]any{
				"status":      "ok",
				"duration_ms": time.Since(start).Milliseconds(),
			}
			toolError := ""
			if err != nil {
				fields["status"] = "error"
				fields["error"] = err.Error()
				toolError = err.Error()
			} else if res, ok := result.(*mcp.CallToolResult); ok && res.IsError {
				fields["status"] = "error"
				toolError = toolResultText(res)
				if toolError != "" {
					fields["error"] = toolError
				}
			}
			if info := req.GetExtra(); info != nil && info.TokenInfo != nil {
				if p, ok := info.TokenInfo.Extra[principalExtraKey].(*oauth.GrantPrincipal); ok {
					fields["grant_id"] = p.GrantID
					fields["client_id"] = p.ClientID
				}
			}
			if call, ok := req.(*mcp.ServerRequest[*mcp.CallToolParamsRaw]); ok {
				fields["tool"] = call.Params.Name
				var args struct {
					Workspace string `json:"workspace"`
					Path      string `json:"path"`
				}
				if len(call.Params.Arguments) > 0 && json.Unmarshal(call.Params.Arguments, &args) == nil {
					if args.Workspace != "" {
						fields["workspace"] = args.Workspace
					}
					if args.Path != "" {
						fields["path"] = args.Path
					}
				}
			}
			if logErr := logger.Log("tool_call", fields); logErr != nil {
				srvLogger.Warn("audit write failed", "event", "tool_call", "error", logErr)
			}
			if isSandboxBlocked(toolError) {
				if logErr := logger.Log("sandbox_blocked", fields); logErr != nil {
					srvLogger.Warn("audit write failed", "event", "sandbox_blocked", "error", logErr)
				}
			}
			return result, err
		}
	}
}

// toolResultText joins the text content of a tool result.
func toolResultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, content := range res.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			b.WriteString(text.Text)
		}
	}
	return b.String()
}

// isSandboxBlocked recognizes the manager's path-escape and denylist errors,
// which the tool layer embeds in an IsError result rather than returning.
func isSandboxBlocked(message string) bool {
	return strings.Contains(message, ws.ErrDeniedPath.Error()) ||
		strings.Contains(message, ws.ErrInvalidPath.Error()) ||
		strings.Contains(message, "blocked by the sensitive-file policy")
}
