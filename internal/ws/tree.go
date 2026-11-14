package ws

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

// TreeEntry is one file or directory in a tree listing.
type TreeEntry struct {
	Path  string `json:"path"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size,omitempty"`
}

// TreeResult is a page of a workspace directory listing.
type TreeResult struct {
	Entries    []TreeEntry `json:"entries"`
	NextCursor string      `json:"next_cursor,omitempty"`
	Truncated  bool        `json:"truncated"`
}

var heavyDirs = map[string]bool{
	"node_modules": true,
	"dist":         true,
	"build":        true,
	"target":       true,
	"__pycache__":  true,
	".venv":        true,
}

// WalkTree lists relPath inside the workspace up to maxDepth levels. Sensitive
// paths, symlinks, and known heavy directories are skipped. Entries are sorted
// depth-first; cursor is an opaque offset into that ordering.
func (w *Workspace) WalkTree(relPath string, maxDepth int, cursor string, limit int) (TreeResult, error) {
	rel, err := w.clean(relPath)
	if err != nil {
		return TreeResult{}, err
	}
	if maxDepth < 1 || maxDepth > 10 {
		return TreeResult{},
			fmt.Errorf("ws: depth must be between 1 and 10, got %d", maxDepth)
	}
	offset := 0
	if cursor != "" {
		offset, err = strconv.Atoi(cursor)
		if err != nil || offset < 0 {
			return TreeResult{}, fmt.Errorf("ws: invalid cursor %q", cursor)
		}
	}
	if limit <= 0 || limit > 2000 {
		limit = 2000
	}

	info, err := w.root.Lstat(rel)
	if err != nil {
		return TreeResult{}, err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return TreeResult{}, fmt.Errorf("%w: symbolic links are not traversed", ErrNotRegularFile)
	}
	if !info.IsDir() {
		return TreeResult{}, fmt.Errorf("%w: %s is not a directory", ErrNotRegularFile, rel)
	}

	res := TreeResult{Entries: make([]TreeEntry, 0, min(limit, 64))}
	seen := 0
	stop := false

	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		if stop {
			return nil
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
			if stop {
				return nil
			}
			name := de.Name()
			childRel := name
			if dir != "." {
				childRel = dir + "/" + name
			}
			if de.Type()&fs.ModeSymlink != 0 {
				continue
			}
			isDir := de.IsDir()
			if !isDir && !de.Type().IsRegular() {
				continue
			}
			if w.IsDenied(childRel) {
				continue
			}
			if isDir && heavyDirs[strings.ToLower(name)] {
				continue
			}
			if seen < offset {
				seen++
				if isDir && depth < maxDepth {
					if err := walk(childRel, depth+1); err != nil {
						return err
					}
				}
				continue
			}
			if len(res.Entries) >= limit {
				res.Truncated = true
				stop = true
				return nil
			}
			entry := TreeEntry{Path: childRel, IsDir: isDir}
			if !isDir {
				if info, err := de.Info(); err == nil {
					entry.Size = info.Size()
				}
			}
			res.Entries = append(res.Entries, entry)
			seen++
			if isDir && depth < maxDepth {
				if err := walk(childRel, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(rel, 1); err != nil {
		return TreeResult{}, err
	}
	if res.Truncated {
		res.NextCursor = strconv.Itoa(offset + len(res.Entries))
	}
	return res, nil
}

var errStopWalk = errors.New("stop walk")
