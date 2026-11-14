package tools

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"wsbridge/internal/ws"
)

type editInput struct {
	Workspace      string          `json:"workspace,omitempty"`
	Path           string          `json:"path"`
	ExpectedSHA256 string          `json:"expected_sha256,omitempty"`
	Edits          []editOperation `json:"edits"`
}

type editOperation struct {
	OldText    string `json:"old_text"`
	NewText    string `json:"new_text"`
	ReplaceAll bool   `json:"replace_all,omitempty"`
}

func (h *handlers) editFile(ctx context.Context, _ *mcp.CallToolRequest, in editInput) (*mcp.CallToolResult, any, error) {
	access, scope, err := h.resolve(ctx, in.Workspace, ws.PermWrite)
	if err != nil {
		return nil, nil, err
	}
	if scope.GrantID == "" {
		return nil, nil, fmt.Errorf("session has no grant identifier")
	}
	if len(in.Edits) == 0 {
		return nil, nil, fmt.Errorf("at least one edit is required")
	}
	data, hash, err := access.Workspace.ReadFile(in.Path)
	if err != nil {
		return nil, nil, errText(describeFileError(in.Path, access.Workspace.Name(), err))
	}
	if isBinary(data) {
		return nil, nil, errText(fmt.Errorf("file %q appears to be binary; edit_file only supports UTF-8 text", in.Path))
	}
	if in.ExpectedSHA256 != "" && !strings.EqualFold(strings.TrimSpace(in.ExpectedSHA256), hash) {
		return nil, nil, errText(fmt.Errorf(
			"expected_sha256 mismatch for file %q; call read_file to get the current SHA-256",
			in.Path))
	}

	content := string(data)
	for i, op := range in.Edits {
		if op.OldText == "" {
			return nil, nil, fmt.Errorf("edit %d: old_text must not be empty", i+1)
		}
		if strings.ContainsRune(op.NewText, 0) {
			return nil, nil, fmt.Errorf("edit %d: new_text must not contain NUL bytes; edit_file only supports text", i+1)
		}
		count := strings.Count(content, op.OldText)
		if count == 0 {
			return nil, nil, errText(fmt.Errorf("edit %d: old_text was not found in %q", i+1, in.Path))
		}
		if !op.ReplaceAll && count > 1 {
			return nil, nil, errText(fmt.Errorf(
				"edit %d: old_text matches multiple times (%d) in %q at lines %s; use a longer unique old_text or set replace_all=true",
				i+1, count, in.Path, joinInts(occurrenceLines(content, op.OldText))))
		}
		content = strings.ReplaceAll(content, op.OldText, op.NewText)
	}
	if content == string(data) {
		return nil, nil, errText(fmt.Errorf("edits produced no changes in %q", in.Path))
	}

	newHash, snapshot, err := access.Workspace.WriteFileAtomic(
		scope.GrantID, in.Path, []byte(content), hash, false)
	if err != nil {
		return nil, nil, errText(describeWriteError(in.Path, err))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Edited %s\nSHA256: %s", in.Path, newHash)
	if snapshot != "" {
		fmt.Fprintf(&b, "\nSnapshot: %s", snapshot)
	}
	if diff := unifiedDiff(data, []byte(content), in.Path); diff != "" {
		b.WriteString("\n")
		b.WriteString(diff)
	}
	return text(truncateOutput(b.String(), "the diff was truncated; read the file for the full result")), nil, nil
}

func occurrenceLines(content, needle string) []int {
	var lines []int
	start := 0
	last := -1
	for {
		idx := strings.Index(content[start:], needle)
		if idx < 0 {
			break
		}
		pos := start + idx
		line := strings.Count(content[:pos], "\n") + 1
		if line != last {
			lines = append(lines, line)
			last = line
		}
		start = pos + len(needle)
	}
	return lines
}

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ", ")
}

func describeWriteError(path string, err error) error {
	switch {
	case errors.Is(err, ws.ErrMissingChecksum), errors.Is(err, ws.ErrFileExists):
		return fmt.Errorf(
			"file %q already exists; call read_file to obtain its SHA-256, then pass expected_sha256 to overwrite it",
			path)
	case errors.Is(err, ws.ErrChecksumForMissing):
		return fmt.Errorf(
			"file %q does not exist, so expected_sha256 cannot match; omit expected_sha256 to create it",
			path)
	case errors.Is(err, ws.ErrChecksumMismatch):
		return fmt.Errorf(
			"file %q changed since it was read; call read_file to get the current SHA-256", path)
	case errors.Is(err, ws.ErrMixedNewlines):
		return fmt.Errorf(
			"file %q has mixed line endings; normalize it before editing", path)
	case errors.Is(err, ws.ErrFileTooLarge):
		return fmt.Errorf("file %q would exceed the 2 MiB write limit", path)
	case errors.Is(err, ws.ErrDeniedPath):
		return fmt.Errorf("file %q is blocked by the sensitive-file policy", path)
	case errors.Is(err, ws.ErrInvalidPath):
		return fmt.Errorf("invalid file path %q", path)
	default:
		return err
	}
}

func unifiedDiff(oldData, newData []byte, name string) string {
	oldLines := fileLines(oldData)
	newLines := fileLines(newData)
	prefix := 0
	limit := min(len(oldLines), len(newLines))
	for prefix < limit && oldLines[prefix] == newLines[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(oldLines)-prefix && suffix < len(newLines)-prefix &&
		oldLines[len(oldLines)-1-suffix] == newLines[len(newLines)-1-suffix] {
		suffix++
	}
	oldChanged := oldLines[prefix : len(oldLines)-suffix]
	newChanged := newLines[prefix : len(newLines)-suffix]
	if len(oldChanged) == 0 && len(newChanged) == 0 {
		return ""
	}
	contextBefore := min(3, prefix)
	contextAfter := min(3, suffix)

	oldStart := prefix - contextBefore + 1
	newStart := oldStart
	oldCount := contextBefore + len(oldChanged) + contextAfter
	newCount := contextBefore + len(newChanged) + contextAfter
	if oldCount == 0 {
		oldStart = prefix
	}
	if newCount == 0 {
		newStart = prefix
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n+++ b/%s\n", name, name)
	fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount)
	for i := prefix - contextBefore; i < prefix; i++ {
		fmt.Fprintf(&b, " %s\n", strings.TrimSuffix(oldLines[i], "\r"))
	}
	for _, line := range oldChanged {
		fmt.Fprintf(&b, "-%s\n", strings.TrimSuffix(line, "\r"))
	}
	for _, line := range newChanged {
		fmt.Fprintf(&b, "+%s\n", strings.TrimSuffix(line, "\r"))
	}
	for i := len(oldLines) - suffix; i < len(oldLines)-suffix+contextAfter; i++ {
		fmt.Fprintf(&b, " %s\n", strings.TrimSuffix(oldLines[i], "\r"))
	}
	return strings.TrimSuffix(b.String(), "\n")
}
