package tools

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"wsbridge/internal/ws"
)

type treeInput struct {
	Workspace string `json:"workspace,omitempty"`
	Path      string `json:"path,omitempty"`
	Depth     int    `json:"depth,omitempty"`
	Cursor    string `json:"cursor,omitempty"`
}

func (h *handlers) getFileTree(ctx context.Context, _ *mcp.CallToolRequest, in treeInput) (*mcp.CallToolResult, any, error) {
	access, _, err := h.resolve(ctx, in.Workspace, ws.PermRead)
	if err != nil {
		return nil, nil, err
	}
	path := in.Path
	if path == "" {
		path = "."
	}
	res, err := access.Workspace.WalkTree(path, in.Depth, in.Cursor, 2000)
	if err != nil {
		if path != "." {
			return nil, nil, errText(fmt.Errorf("list %q in workspace %q: %w", path, access.Workspace.Name(), err))
		}
		return nil, nil, errText(fmt.Errorf("list workspace %q: %w", access.Workspace.Name(), err))
	}

	// WalkTree returns at most 2000 entries, but those entries can still be
	// far larger than the 64KB tool-output budget. Render only the entries
	// that fit and derive the cursor from that count, so the footer is never
	// truncated and every entry is reachable across pages.
	offset := 0
	if in.Cursor != "" {
		if v, err := strconv.Atoi(in.Cursor); err == nil && v >= 0 {
			offset = v
		}
	}
	displayPath := truncateUTF8(path, 1024)
	displayName := truncateUTF8(access.Workspace.Name(), 200)
	const headerFormat = "Workspace: %s | path: %s | depth: %d | entries: %d"
	// Reserve the header (sized for the full walker page) and the cursor footer.
	footerReserve := 128
	budget := MaxOutputBytes - footerReserve -
		len(fmt.Sprintf(headerFormat, displayName, displayPath, in.Depth, len(res.Entries)))
	if budget < 1024 {
		budget = 1024
	}

	lines := make([]string, 0, len(res.Entries))
	used := 0
	for _, entry := range res.Entries {
		line := treeEntryLine(entry)
		if used+len(line)+1 > budget {
			break
		}
		lines = append(lines, line)
		used += len(line) + 1
	}
	if len(lines) == 0 && len(res.Entries) > 0 {
		// A single path longer than the whole budget must still make progress.
		line := treeEntryLine(res.Entries[0])
		if len(line) > budget-1 {
			line = truncateUTF8(line, budget-1-len("…")) + "…"
		}
		lines = append(lines, line)
	}
	cursor := ""
	switch {
	case len(lines) < len(res.Entries):
		cursor = strconv.Itoa(offset + len(lines))
	case res.Truncated:
		cursor = res.NextCursor
	}

	var b strings.Builder
	fmt.Fprintf(&b, headerFormat, displayName, displayPath, in.Depth, len(lines))
	if len(lines) == 0 {
		b.WriteString("\n(no entries)")
	}
	for _, line := range lines {
		b.WriteString("\n")
		b.WriteString(line)
	}
	if cursor != "" {
		fmt.Fprintf(&b, "\n\n[truncated; continue with cursor: %q]", cursor)
	}
	return text(b.String()), nil, nil
}

func treeEntryLine(entry ws.TreeEntry) string {
	indent := strings.Repeat("  ", strings.Count(entry.Path, "/"))
	if entry.IsDir {
		return indent + entry.Path + "/"
	}
	return fmt.Sprintf("%s%s (%d bytes)", indent, entry.Path, entry.Size)
}

type searchInput struct {
	Workspace  string `json:"workspace,omitempty"`
	Query      string `json:"query"`
	Path       string `json:"path,omitempty"`
	Regex      bool   `json:"regex,omitempty"`
	IgnoreCase bool   `json:"ignore_case,omitempty"`
	MaxResults int    `json:"max_results,omitempty"`
}

func (h *handlers) searchCode(ctx context.Context, _ *mcp.CallToolRequest, in searchInput) (*mcp.CallToolResult, any, error) {
	access, _, err := h.resolve(ctx, in.Workspace, ws.PermRead)
	if err != nil {
		return nil, nil, err
	}
	matches, truncated, err := access.Workspace.Search(ctx, ws.SearchOptions{
		Query:      in.Query,
		Regex:      in.Regex,
		IgnoreCase: in.IgnoreCase,
		Subdir:     in.Path,
		MaxResults: in.MaxResults,
	})
	if err != nil {
		return nil, nil, errText(err)
	}
	if len(matches) == 0 {
		return text(truncateOutput(fmt.Sprintf("No matches for %q.", in.Query), "shorten the query")), nil, nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Found %d match(es) for %q", len(matches), in.Query)
	if truncated {
		b.WriteString(" (truncated at max_results)")
	}
	b.WriteString(":")
	for _, m := range matches {
		fmt.Fprintf(&b, "\n%s:%d:%s", m.Path, m.Line, m.Text)
	}
	out := b.String()
	if truncated {
		out += "\n\n[showing the first results; narrow the query or path to see more]"
	}
	return text(truncateOutput(out, "narrow the query or path")), nil, nil
}
