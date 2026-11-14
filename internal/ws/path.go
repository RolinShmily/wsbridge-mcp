// Package ws implements the os.Root-based workspace sandbox used by the
// wsbridge MCP tools.
package ws

import (
	"fmt"
	"path"
	"runtime"
	"strings"
)

// Permission is the ordered workspace permission level.
type Permission int

const (
	PermNone  Permission = iota // no access
	PermRead                    // read-only tools
	PermWrite                   // read plus file modifications
	PermCheck                   // write plus whitelisted checks
)

// String returns the configuration spelling of p.
func (p Permission) String() string {
	switch p {
	case PermRead:
		return "read"
	case PermWrite:
		return "write"
	case PermCheck:
		return "check"
	default:
		return "none"
	}
}

// ParsePermission maps a configuration string to a Permission.
func ParsePermission(s string) (Permission, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "read":
		return PermRead, nil
	case "write":
		return PermWrite, nil
	case "check":
		return PermCheck, nil
	default:
		return PermNone, fmt.Errorf("invalid permission %q (want read, write, or check)", s)
	}
}

// MinPermission returns the lower of two permission levels.
func MinPermission(a, b Permission) Permission {
	if a < b {
		return a
	}
	return b
}

var defaultDenyPatterns = []string{
	".git", ".ssh", ".aws",
	".env", ".env.*", ".npmrc", ".netrc",
	"*.pem", "*.key", "*.p12", "*.pfx",
	"id_rsa", "id_rsa.*", "id_ed25519", "id_ed25519.*", "*.kdbx",
}

// hardDeniedSegments can never be re-enabled by configuration.
var hardDeniedSegments = map[string]bool{
	".git": true,
	".ssh": true,
}

var reservedDeviceNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"CONIN$": true, "CONOUT$": true,
}

// SanitizeRelPath normalizes an externally supplied workspace-relative path
// and rejects cross-platform escape vectors. The empty path and "." refer to
// the workspace root and are returned as ".".
func SanitizeRelPath(raw string) (string, error) {
	if strings.ContainsRune(raw, 0) {
		return "", fmt.Errorf("path contains a NUL byte")
	}
	p := strings.ReplaceAll(raw, `\`, "/")
	if strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("absolute paths are not allowed")
	}
	if strings.Contains(p, ":") {
		return "", fmt.Errorf("colons are not allowed in paths (drive letters and alternate data streams)")
	}
	segments := strings.Split(p, "/")
	out := make([]string, 0, len(segments))
	for _, segment := range segments {
		switch segment {
		case "", ".":
			continue
		case "..":
			return "", fmt.Errorf("parent directory traversal is not allowed")
		}
		if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return "", fmt.Errorf("path segment %q ends with a dot or space", segment)
		}
		if isReservedDeviceName(segment) {
			return "", fmt.Errorf("path segment %q is a reserved device name", segment)
		}
		// Windows resolves NTFS 8.3 aliases (for example GIT~1) to their long
		// names, which would otherwise bypass a denylist entry such as .git.
		if runtime.GOOS == "windows" && isShortNameAlias(segment) {
			return "", fmt.Errorf("path segment %q looks like an 8.3 short-name alias", segment)
		}
		out = append(out, segment)
	}
	if len(out) == 0 {
		return ".", nil
	}
	return strings.Join(out, "/"), nil
}

func isReservedDeviceName(segment string) bool {
	base := segment
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	base = strings.ToUpper(base)
	if reservedDeviceNames[base] {
		return true
	}
	// Windows reserves COM1-COM9 and LPT1-LPT9, including the superscript
	// digits ¹, ², and ³ (U+00B9, U+00B2, U+00B3).
	for _, prefix := range []string{"COM", "LPT"} {
		if !strings.HasPrefix(base, prefix) {
			continue
		}
		switch strings.TrimPrefix(base, prefix) {
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
			return true
		}
	}
	return false
}

// isShortNameAlias reports whether segment resembles an NTFS 8.3 alias: a
// base name ending in a tilde followed only by digits (GIT~1, PROGRA~2.TXT).
func isShortNameAlias(segment string) bool {
	base := segment
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	i := strings.LastIndexByte(base, '~')
	if i < 0 || i == len(base)-1 {
		return false
	}
	for _, r := range base[i+1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// IsDeniedPath reports whether rel matches the built-in sensitive-file policy.
func IsDeniedPath(rel string) bool {
	return matchesDeny(defaultDenyPatterns, rel)
}

func matchesDeny(patterns []string, rel string) bool {
	p := strings.ReplaceAll(rel, `\`, "/")
	segments := strings.Split(p, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." {
			continue
		}
		lower := strings.ToLower(segment)
		if hardDeniedSegments[lower] {
			return true
		}
		for _, pattern := range patterns {
			if globMatch(strings.ToLower(pattern), lower) {
				return true
			}
		}
	}
	full := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(p, "./"), "/"))
	if full != "" {
		for _, pattern := range patterns {
			if globMatch(strings.ToLower(pattern), full) {
				return true
			}
		}
	}
	return false
}

func globMatch(pattern, name string) bool {
	if pattern == name {
		return true
	}
	return matchSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

// matchSegments applies slash-separated patterns segment by segment. It adds
// the recursive ** form used by ripgrep globs, which path.Match does not
// support; * and ? still never cross a segment boundary.
func matchSegments(pattern, name []string) bool {
	for len(pattern) > 0 {
		if pattern[0] == "**" {
			for len(pattern) > 0 && pattern[0] == "**" {
				pattern = pattern[1:]
			}
			if len(pattern) == 0 {
				return true
			}
			for i := 0; i <= len(name); i++ {
				if matchSegments(pattern, name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		ok, err := path.Match(pattern[0], name[0])
		if err != nil || !ok {
			return false
		}
		pattern = pattern[1:]
		name = name[1:]
	}
	return len(name) == 0
}
