// Package tools registers the seven wsbridge MCP tools.
package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"wsbridge/internal/ws"
)

// MaxOutputBytes is the hard limit for a single tool's text output.
const MaxOutputBytes = 64 << 10

// Access pairs a sandboxed workspace with the permission granted to the
// current session for it.
type Access struct {
	Workspace  *ws.Workspace
	Permission ws.Permission
}

// Scope is the set of workspaces visible to one MCP session. M1 uses a fixed
// development scope; M2 will derive it from the OAuth grant.
type Scope struct {
	GrantID string
	Allowed []Access
}

// ScopeFunc resolves the scope for an incoming tool call.
type ScopeFunc func(context.Context) (*Scope, error)

// Resolve selects a workspace and verifies that need is permitted. An empty
// name is accepted only when exactly one workspace is authorized.
func (s *Scope) Resolve(name string, need ws.Permission) (Access, error) {
	if s == nil || len(s.Allowed) == 0 {
		return Access{}, fmt.Errorf("no workspaces are authorized for this session")
	}
	if name == "" {
		if len(s.Allowed) == 1 {
			return checkAccess(s.Allowed[0], need)
		}
		return Access{}, fmt.Errorf(
			"this session authorizes multiple workspaces (%s); specify \"workspace\"",
			strings.Join(s.Names(), ", "))
	}
	for _, access := range s.Allowed {
		if access.Workspace.Name() == name {
			return checkAccess(access, need)
		}
	}
	return Access{}, fmt.Errorf("workspace %q is not authorized; available: %s",
		name, strings.Join(s.Names(), ", "))
}

func checkAccess(access Access, need ws.Permission) (Access, error) {
	if access.Permission < need {
		return Access{}, fmt.Errorf("workspace %q requires %s permission, but this session only allows %s",
			access.Workspace.Name(), need, access.Permission)
	}
	return access, nil
}

// Names returns authorized workspace names in scope order.
func (s *Scope) Names() []string {
	if s == nil {
		return nil
	}
	names := make([]string, 0, len(s.Allowed))
	for _, access := range s.Allowed {
		names = append(names, access.Workspace.Name())
	}
	return names
}

type handlers struct {
	getScope ScopeFunc
}

// Register adds all seven tools to s.
func Register(s *mcp.Server, getScope ScopeFunc) {
	h := &handlers{getScope: getScope}

	mcp.AddTool(s, tool("list_workspaces",
		"List the local workspaces authorized for this session, their effective permission level, and allowed checks.",
		listWorkspacesSchema, "List workspaces", true, false, true),
		h.listWorkspaces)
	mcp.AddTool(s, tool("get_file_tree",
		"View the directory tree of a workspace. Skips .git, node_modules, other heavy directories, and sensitive files.",
		getFileTreeSchema, "Get file tree", true, false, true),
		h.getFileTree)
	mcp.AddTool(s, tool("search_code",
		"Search text files in a workspace using a regular expression or literal string. Returns path:line:text matches; sensitive files are filtered.",
		searchCodeSchema, "Search code", true, false, true),
		h.searchCode)
	mcp.AddTool(s, tool("read_file",
		"Read a text file from a workspace with line numbers and its current SHA-256. Supports multiple 1-based inclusive ranges.",
		readFileSchema, "Read file", true, false, true),
		h.readFile)
	mcp.AddTool(s, tool("edit_file",
		"Apply one or more exact text replacements to an existing file atomically. Preserves newlines/BOM, creates a snapshot, and returns a unified diff plus the new SHA-256.",
		editFileSchema, "Edit file", false, true, false),
		h.editFile)
	mcp.AddTool(s, tool("write_file",
		"Create a new file, or overwrite an existing file when expected_sha256 matches. Creates parent directories inside the workspace.",
		writeFileSchema, "Write file", false, true, false),
		h.writeFile)
	mcp.AddTool(s, tool("run_check",
		"Run a check from the workspace's configured whitelist (for example git_status, git_diff, or go_vet), with a 60s timeout.",
		runCheckSchema, "Run check", false, false, true),
		h.runCheck)
}

func tool(name, description, schema, title string, readOnly, destructive, idempotent bool) *mcp.Tool {
	openWorld := false
	destructiveHint := destructive
	return &mcp.Tool{
		Name:        name,
		Description: description,
		InputSchema: rawSchema(schema),
		Annotations: &mcp.ToolAnnotations{
			Title:           title,
			ReadOnlyHint:    readOnly,
			DestructiveHint: &destructiveHint,
			IdempotentHint:  idempotent,
			OpenWorldHint:   &openWorld,
		},
	}
}

func (h *handlers) scope(ctx context.Context) (*Scope, error) {
	if h.getScope == nil {
		return nil, fmt.Errorf("tool session is not configured")
	}
	scope, err := h.getScope(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve session scope: %w", err)
	}
	return scope, nil
}

func (h *handlers) listWorkspaces(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	scope, err := h.scope(ctx)
	if err != nil {
		return nil, nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Authorized workspaces (%d):", len(scope.Allowed))
	for _, access := range scope.Allowed {
		fmt.Fprintf(&b, "\n- name: %s | effective_perm: %s | allowed_checks: [%s]",
			access.Workspace.Name(), access.Permission,
			strings.Join(access.Workspace.AllowedChecks(), ", "))
	}
	return text(truncateOutput(b.String(), "the workspace list is very large")), nil, nil
}

func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// truncateOutput enforces MaxOutputBytes without splitting a UTF-8 rune and
// appends an actionable hint.
func truncateOutput(s, hint string) string {
	if len(s) <= MaxOutputBytes {
		return s
	}
	suffix := "\n\n[output truncated at 64KB"
	if hint != "" {
		suffix += "; " + hint
	}
	suffix += "]"
	cut := MaxOutputBytes - len(suffix)
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

// maxToolErrorBytes bounds error text that may echo caller-supplied input,
// such as an invalid regular expression or an extremely long path.
const maxToolErrorBytes = 2048

func errText(err error) error {
	if err == nil {
		return nil
	}
	if len(err.Error()) <= maxToolErrorBytes {
		return err
	}
	return errors.New(truncateUTF8(err.Error(), maxToolErrorBytes) + " …")
}
