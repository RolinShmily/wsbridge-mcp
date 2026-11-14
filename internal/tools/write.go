package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"wsbridge/internal/ws"
)

// writeInput is limited by ws.MaxFileSize (2 MiB) at the workspace layer. In
// HTTP deployments the documented 1 MiB global request-body cap applies to
// the whole JSON-RPC request, so the effective content limit there is lower.
type writeInput struct {
	Workspace      string `json:"workspace,omitempty"`
	Path           string `json:"path"`
	Content        string `json:"content"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}

func (h *handlers) writeFile(ctx context.Context, _ *mcp.CallToolRequest, in writeInput) (*mcp.CallToolResult, any, error) {
	access, scope, err := h.resolve(ctx, in.Workspace, ws.PermWrite)
	if err != nil {
		return nil, nil, err
	}
	if scope.GrantID == "" {
		return nil, nil, fmt.Errorf("session has no grant identifier")
	}
	if strings.ContainsRune(in.Content, 0) {
		return nil, nil, fmt.Errorf("content must not contain NUL bytes; write_file only supports text")
	}
	expect := strings.TrimSpace(in.ExpectedSHA256)
	hash, snapshot, err := access.Workspace.WriteFileAtomic(
		scope.GrantID, in.Path, []byte(in.Content), expect, expect == "")
	if err != nil {
		return nil, nil, errText(describeWriteError(in.Path, err))
	}

	// Report the size that was actually persisted: newline normalization and
	// BOM preservation can change it from len(in.Content).
	size := len(in.Content)
	if info, statErr := access.Workspace.StatFile(in.Path); statErr == nil {
		size = int(info.Size())
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Wrote %s (%d bytes)\nSHA256: %s", in.Path, size, hash)
	if snapshot != "" {
		fmt.Fprintf(&b, "\nSnapshot: %s", snapshot)
	}
	return text(b.String()), nil, nil
}

type checkInput struct {
	Workspace string `json:"workspace,omitempty"`
	Name      string `json:"name"`
}

func (h *handlers) runCheck(ctx context.Context, _ *mcp.CallToolRequest, in checkInput) (*mcp.CallToolResult, any, error) {
	access, _, err := h.resolve(ctx, in.Workspace, ws.PermCheck)
	if err != nil {
		return nil, nil, err
	}
	output, exitCode, err := access.Workspace.RunCheck(ctx, in.Name)
	if err != nil {
		return nil, nil, errText(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Check: %s\nExit: %d\n---\n%s", in.Name, exitCode, output)
	return text(truncateOutput(b.String(), "run a narrower check or inspect the command output directly")), nil, nil
}
