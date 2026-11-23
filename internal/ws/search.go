package ws

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrSearchTimeout indicates that a workspace search exceeded its 20s budget.
var ErrSearchTimeout = errors.New("search timed out")

// SearchOptions configures Workspace.Search.
type SearchOptions struct {
	Query      string
	Regex      bool
	IgnoreCase bool
	Subdir     string
	MaxResults int
}

// SearchMatch is one matching line in a workspace file.
type SearchMatch struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

const (
	maxSearchResults = 500
	searchTimeout    = 20 * time.Second
)

// Search finds Query in workspace text files. Ripgrep is used when available;
// every path it returns is re-validated against the sandbox denylist. The
// pure-Go fallback walks the os.Root sandbox directly.
func (w *Workspace) Search(ctx context.Context, opts SearchOptions) ([]SearchMatch, bool, error) {
	w.rootMu.RLock()
	defer w.rootMu.RUnlock()
	if w.closed {
		return nil, false, ErrWorkspaceClosed
	}
	if strings.TrimSpace(opts.Query) == "" {
		return nil, false, fmt.Errorf("ws: search query must not be empty")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	subdir, err := w.clean(opts.Subdir)
	if err != nil {
		return nil, false, err
	}
	maxResults := opts.MaxResults
	if maxResults <= 0 {
		maxResults = 100
	}
	if maxResults > maxSearchResults {
		maxResults = maxSearchResults
	}
	pattern := opts.Query
	if !opts.Regex {
		pattern = regexp.QuoteMeta(pattern)
	}
	if opts.IgnoreCase {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, false, fmt.Errorf("ws: invalid regular expression: %w", err)
	}

	info, err := w.root.Lstat(subdir)
	if err != nil {
		return nil, false, err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("%w: symbolic links are not searched", ErrNotRegularFile)
	}

	if w.ripgrepPath != "" {
		matches, truncated, rgErr := w.searchRipgrep(ctx, opts, subdir, maxResults)
		if rgErr == nil {
			sortMatches(matches)
			return matches, truncated, nil
		}
		if errors.Is(rgErr, ErrSearchTimeout) || ctx.Err() != nil {
			return nil, false, rgErr
		}
		// Ripgrep failed for an operational reason; fall back to pure Go.
	}

	// The pure-Go fallback gets the same 20s budget as ripgrep, including when
	// it follows an operational ripgrep failure.
	goCtx, cancel := context.WithTimeout(ctx, searchTimeout)
	defer cancel()
	matches, truncated, err := w.searchGo(goCtx, re, subdir, maxResults)
	if err != nil {
		if errors.Is(goCtx.Err(), context.DeadlineExceeded) {
			return nil, false, fmt.Errorf("%w: search exceeded 20s", ErrSearchTimeout)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, false, ctxErr
		}
		return nil, false, err
	}
	sortMatches(matches)
	return matches, truncated, nil
}

func sortMatches(matches []SearchMatch) {
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Path != matches[j].Path {
			return matches[i].Path < matches[j].Path
		}
		return matches[i].Line < matches[j].Line
	})
}

func (w *Workspace) searchRipgrep(ctx context.Context, opts SearchOptions, subdir string, maxResults int) ([]SearchMatch, bool, error) {
	runCtx, cancel := context.WithTimeout(ctx, searchTimeout)
	defer cancel()

	args := []string{
		"--line-number", "--no-heading", "--color=never",
		"--hidden", "--no-ignore",
		"--no-config", "--no-messages",
		"--max-filesize", "2M",
	}
	for _, dir := range []string{"node_modules", "dist", "build", "target", "__pycache__", ".venv"} {
		args = append(args, "--glob", "!"+dir+"/**", "--glob", "!**/"+dir+"/**")
	}
	for _, pattern := range w.denyPatterns {
		args = append(args, "--glob", "!"+pattern)
		if !strings.Contains(pattern, "/") {
			args = append(args, "--glob", "!**/"+pattern)
		}
	}
	if opts.IgnoreCase {
		args = append(args, "-i")
	}
	if !opts.Regex {
		args = append(args, "--fixed-strings")
	}
	args = append(args, "--", opts.Query, subdir)

	cmd := exec.CommandContext(runCtx, w.ripgrepPath, args...)
	cmd.Dir = w.hostPath
	cmd.Env = filteredCheckEnv()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	if err := cmd.Start(); err != nil {
		return nil, false, err
	}

	matches := make([]SearchMatch, 0, min(maxResults, 64))
	truncated := false
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for scanner.Scan() {
		m, ok := parseRipgrepLine(scanner.Text())
		if !ok {
			continue
		}
		rel, ok := w.acceptMatchPath(m.Path)
		if !ok {
			continue
		}
		if len(matches) >= maxResults {
			truncated = true
			cancel()
			break
		}
		m.Path = rel
		matches = append(matches, m)
	}
	scanErr := scanner.Err()
	waitErr := cmd.Wait()

	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return nil, false, fmt.Errorf("%w: search exceeded 20s", ErrSearchTimeout)
	}
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	if truncated {
		return matches, true, nil
	}
	if scanErr != nil {
		return nil, false, fmt.Errorf("read ripgrep output: %w", scanErr)
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) && exitErr.ExitCode() == 1 {
			return nil, false, nil // no matches
		}
		return nil, false, fmt.Errorf("ripgrep: %w", waitErr)
	}
	return matches, false, nil
}

func parseRipgrepLine(line string) (SearchMatch, bool) {
	first := strings.IndexByte(line, ':')
	if first <= 0 {
		return SearchMatch{}, false
	}
	rest := line[first+1:]
	second := strings.IndexByte(rest, ':')
	if second <= 0 {
		return SearchMatch{}, false
	}
	lineNo, err := strconv.Atoi(rest[:second])
	if err != nil || lineNo < 1 {
		return SearchMatch{}, false
	}
	text := strings.TrimSuffix(rest[second+1:], "\r")
	return SearchMatch{Path: line[:first], Line: lineNo, Text: text}, true
}

// acceptMatchPath normalizes a reported path and applies the sensitive-file
// policy a second time, independently of ripgrep's own glob filters.
func (w *Workspace) acceptMatchPath(raw string) (string, bool) {
	rel, err := SanitizeRelPath(raw)
	if err != nil || rel == "." {
		return "", false
	}
	if w.IsDenied(rel) {
		return "", false
	}
	return rel, true
}

func (w *Workspace) searchGo(ctx context.Context, re *regexp.Regexp, subdir string, maxResults int) ([]SearchMatch, bool, error) {
	var matches []SearchMatch
	truncated := false
	err := w.walkFiles(ctx, subdir, func(rel string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := w.root.Lstat(rel)
		if err != nil || !info.Mode().IsRegular() || info.Size() > MaxFileSize {
			return nil
		}
		data, err := w.root.ReadFile(rel)
		if err != nil {
			return nil // unreadable files are skipped, not fatal
		}
		if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
			return nil
		}
		for i, raw := range bytes.Split(data, []byte("\n")) {
			if i%1024 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			raw = bytes.TrimSuffix(raw, []byte("\r"))
			if !re.Match(raw) {
				continue
			}
			if len(matches) >= maxResults {
				truncated = true
				return errStopWalk
			}
			matches = append(matches, SearchMatch{Path: rel, Line: i + 1, Text: string(raw)})
		}
		return nil
	})
	if errors.Is(err, errStopWalk) {
		err = nil
	}
	return matches, truncated, err
}

// walkFiles calls fn for each regular file under rel, sorted and sandboxed.
func (w *Workspace) walkFiles(ctx context.Context, rel string, fn func(rel string) error) error {
	info, err := w.root.Lstat(rel)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: symbolic links are not searched", ErrNotRegularFile)
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return ErrNotRegularFile
		}
		return fn(rel)
	}
	return w.walkDir(ctx, rel, fn)
}

func (w *Workspace) walkDir(ctx context.Context, dir string, fn func(rel string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := w.root.Open(dir)
	if err != nil {
		return err
	}
	entries, err := f.ReadDir(-1)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, de := range entries {
		name := de.Name()
		childRel := name
		if dir != "." {
			childRel = dir + "/" + name
		}
		if de.Type()&fs.ModeSymlink != 0 || w.IsDenied(childRel) {
			continue
		}
		if de.IsDir() {
			if heavyDirs[strings.ToLower(name)] {
				continue
			}
			if err := w.walkDir(ctx, childRel, fn); err != nil {
				return err
			}
			continue
		}
		if !de.Type().IsRegular() {
			continue
		}
		if err := fn(childRel); err != nil {
			return err
		}
	}
	return nil
}
