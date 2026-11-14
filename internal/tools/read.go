package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"wsbridge/internal/ws"
)

type readInput struct {
	Workspace string       `json:"workspace,omitempty"`
	Path      string       `json:"path"`
	Ranges    []rangeInput `json:"ranges,omitempty"`
}

type rangeInput struct {
	StartLine int `json:"start_line"`
	EndLine   int `json:"end_line"`
}

type lineRange struct {
	start int
	end   int
}

func (h *handlers) readFile(ctx context.Context, _ *mcp.CallToolRequest, in readInput) (*mcp.CallToolResult, any, error) {
	access, _, err := h.resolve(ctx, in.Workspace, ws.PermRead)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range in.Ranges {
		if r.StartLine < 1 || r.EndLine < 1 || r.EndLine < r.StartLine {
			return nil, nil, fmt.Errorf(
				"invalid range: start_line=%d end_line=%d (require 1 <= start_line <= end_line)",
				r.StartLine, r.EndLine)
		}
	}
	data, hash, err := access.Workspace.ReadFile(in.Path)
	if err != nil {
		return nil, nil, errText(describeFileError(in.Path, access.Workspace.Name(), err))
	}
	if isBinary(data) {
		return nil, nil, errText(fmt.Errorf("file %q appears to be binary; read_file only supports UTF-8 text", in.Path))
	}
	lines := fileLines(data)
	if len(lines) == 0 {
		return text(fmt.Sprintf("File: %s | SHA256: %s\n(empty file)", in.Path, hash)), nil, nil
	}

	ranges, truncated, err := selectRanges(in.Ranges, len(lines))
	if err != nil {
		return nil, nil, err
	}

	const hint = "use ranges to read a narrower span"
	suffix := "\n\n[output truncated at 64KB; " + hint + "]"
	budget := MaxOutputBytes - len(suffix)

	var b strings.Builder
	fmt.Fprintf(&b, "File: %s | SHA256: %s\n", in.Path, hash)
	emitted := 0
	for _, r := range ranges {
		for no := r.start; no <= r.end; no++ {
			if emitted >= 2000 {
				truncated = true
				break
			}
			line := strings.TrimSuffix(lines[no-1], "\r")
			rendered := fmt.Sprintf("%d | %s\n", no, line)
			if b.Len()+len(rendered) > budget {
				remaining := budget - b.Len()
				prefix := fmt.Sprintf("%d | ", no)
				// Reserve the trailing newline so the final output, including
				// the suffix, cannot exceed MaxOutputBytes.
				if remaining > len(prefix)+utf8.UTFMax+1 {
					avail := remaining - len(prefix) - 1
					line = truncateUTF8(line, avail)
					b.WriteString(prefix)
					b.WriteString(line)
					b.WriteString("\n")
				}
				truncated = true
				break
			}
			b.WriteString(rendered)
			emitted++
		}
		if truncated {
			break
		}
	}
	out := b.String()
	if truncated {
		out += suffix
	}
	return text(out), nil, nil
}

func selectRanges(raw []rangeInput, total int) ([]lineRange, bool, error) {
	if len(raw) == 0 {
		if total > 2000 {
			return []lineRange{{start: 1, end: total}}, true, nil
		}
		return []lineRange{{start: 1, end: total}}, false, nil
	}
	ranges := make([]lineRange, 0, len(raw))
	for _, r := range raw {
		if r.StartLine > total {
			return nil, false, fmt.Errorf(
				"range start_line %d exceeds the file's %d lines", r.StartLine, total)
		}
		end := r.EndLine
		if end > total {
			end = total
		}
		ranges = append(ranges, lineRange{start: r.StartLine, end: end})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	merged := ranges[:1]
	for _, r := range ranges[1:] {
		last := &merged[len(merged)-1]
		if r.start <= last.end+1 {
			if r.end > last.end {
				last.end = r.end
			}
			continue
		}
		merged = append(merged, r)
	}
	return merged, false, nil
}

func fileLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func isBinary(data []byte) bool {
	return bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data)
}

func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	if maxBytes < 0 {
		return ""
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func describeFileError(path, workspace string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("file %q does not exist in workspace %q", path, workspace)
	case errors.Is(err, ws.ErrDeniedPath):
		return fmt.Errorf("file %q is blocked by the sensitive-file policy", path)
	case errors.Is(err, ws.ErrFileTooLarge):
		return fmt.Errorf("file %q exceeds the 2 MiB read limit", path)
	case errors.Is(err, ws.ErrNotRegularFile):
		return fmt.Errorf("%q is not a regular file readable as text", path)
	default:
		return err
	}
}

// resolve selects the workspace for a call and reports the session scope.
func (h *handlers) resolve(ctx context.Context, workspaceName string, need ws.Permission) (Access, *Scope, error) {
	scope, err := h.scope(ctx)
	if err != nil {
		return Access{}, nil, errText(err)
	}
	access, err := scope.Resolve(workspaceName, need)
	if err != nil {
		return Access{}, nil, errText(err)
	}
	return access, scope, nil
}
