// Package config loads, validates, and writes the wsbridge TOML configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/RolinShmily/wsbridge-mcp/internal/ws"
)

const (
	// DefaultListen binds the HTTP server to the loopback interface only.
	DefaultListen = "127.0.0.1:8787"
	// DefaultMaxSnapshotsPerGrant is the number of pre-write snapshots kept per Grant.
	DefaultMaxSnapshotsPerGrant = 20
)

// Permission is the ordered workspace permission level granted to a session.
type Permission string

const (
	PermRead  Permission = "read"
	PermWrite Permission = "write"
	PermCheck Permission = "check"
)

// Valid reports whether p is a supported permission level.
func (p Permission) Valid() bool {
	switch p {
	case PermRead, PermWrite, PermCheck:
		return true
	default:
		return false
	}
}

// Workspace is one local directory exposed through the MCP tools.
type Workspace struct {
	Name    string     `toml:"name"`
	Path    string     `toml:"path"`
	MaxPerm Permission `toml:"max_perm"`
	Checks  []string   `toml:"checks"`
}

// Config is the complete config.toml document.
type Config struct {
	PublicURL            string      `toml:"public_url"`
	Listen               string      `toml:"listen"`
	DataDir              string      `toml:"data_dir,omitempty"`
	MaxPerm              Permission  `toml:"max_perm,omitempty"`
	AllowRedirectHosts   []string    `toml:"allow_redirect_hosts,omitempty"`
	DenyPatterns         []string    `toml:"deny_patterns,omitempty"`
	MaxSnapshotsPerGrant int         `toml:"max_snapshots_per_grant"`
	Tunnel               Tunnel      `toml:"tunnel,omitempty"`
	Workspaces           []Workspace `toml:"workspace,omitempty"`

	// path is the absolute path this configuration was loaded from or saved to.
	path string
}

// EffectiveMaxPerm returns the configured local permission ceiling, defaulting
// to PermCheck (full access) when omitted so the OAuth consent page controls
// each connection's permission.
func (c *Config) EffectiveMaxPerm() Permission {
	if c.MaxPerm != "" {
		return c.MaxPerm
	}
	return PermCheck
}

// Tunnel configures an optional managed tunnel subprocess (for example cloudflared).
type Tunnel struct {
	Provider  string `toml:"provider,omitempty"`
	Binary    string `toml:"binary,omitempty"`
	TokenFile string `toml:"token_file,omitempty"`
	TokenEnv  string `toml:"token_env,omitempty"`
}

// LoadOptions controls validation that is intentionally relaxed for local tests.
type LoadOptions struct {
	// AllowHTTPPublicURL permits an http:// public_url. It is meant for
	// loopback-based end-to-end tests only; production configurations must be HTTPS.
	AllowHTTPPublicURL bool
}

var workspaceNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// DefaultPath returns <os.UserConfigDir()>/wsbridge/config.toml.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config: resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "wsbridge", "config.toml"), nil
}

// Load reads and validates the TOML file at path, applying defaults.
func Load(path string) (*Config, error) {
	return LoadWithOptions(path, LoadOptions{})
}

// LoadWithOptions reads and validates the TOML file at path with explicit options.
func LoadWithOptions(path string, opts LoadOptions) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: resolve path %q: %w", path, err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", abs, err)
	}
	var cfg Config
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		var missing *toml.StrictMissingError
		if errors.As(err, &missing) {
			keys := make([]string, 0, len(missing.Errors))
			for i := range missing.Errors {
				keys = append(keys, strings.Join(missing.Errors[i].Key(), "."))
			}
			return nil, fmt.Errorf("config: parse %q: unknown configuration keys: %s", abs, strings.Join(keys, ", "))
		}
		return nil, fmt.Errorf("config: parse %q: %w", abs, err)
	}
	cfg.path = abs
	if err := cfg.ValidateWith(opts); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ConfigPath returns the absolute path this Config was loaded from or saved to.
func (c *Config) ConfigPath() string { return c.path }

// ResolvedDataDir returns the configured data directory, defaulting to the
// directory that holds config.toml.
func (c *Config) ResolvedDataDir() (string, error) {
	if c.DataDir != "" {
		return filepath.Clean(c.DataDir), nil
	}
	if c.path == "" {
		return "", fmt.Errorf("config: data_dir is not set and config path is unknown")
	}
	return filepath.Dir(c.path), nil
}

// Validate applies defaults and checks the configuration. It requires an
// HTTPS public_url; use ValidateWith to allow http:// for loopback tests.
func (c *Config) Validate() error {
	return c.ValidateWith(LoadOptions{})
}

// ValidateWith applies defaults and checks the configuration.
func (c *Config) ValidateWith(opts LoadOptions) error {
	c.normalize()
	if err := c.validatePublicURL(opts); err != nil {
		return err
	}
	if err := validateListen(c.Listen); err != nil {
		return err
	}
	if c.DataDir != "" && !filepath.IsAbs(c.DataDir) {
		return fmt.Errorf("config: data_dir %q must be an absolute path", c.DataDir)
	}
	if c.MaxPerm != "" && !c.MaxPerm.Valid() {
		return fmt.Errorf("config: invalid max_perm %q (want read, write, or check)", c.MaxPerm)
	}
	if c.MaxSnapshotsPerGrant < 0 {
		return fmt.Errorf("config: max_snapshots_per_grant must be >= 0")
	}
	if err := validateRedirectHosts(c.AllowRedirectHosts); err != nil {
		return err
	}
	if err := validateDenyPatterns(c.DenyPatterns); err != nil {
		return err
	}
	if err := c.validateTunnel(); err != nil {
		return err
	}
	return validateWorkspaces(c.Workspaces, c.EffectiveMaxPerm())
}

func (c *Config) normalize() {
	c.PublicURL = strings.TrimSpace(c.PublicURL)
	c.Listen = strings.TrimSpace(c.Listen)
	c.DataDir = strings.TrimSpace(c.DataDir)
	c.MaxPerm = Permission(strings.TrimSpace(string(c.MaxPerm)))
	c.Tunnel.Provider = strings.ToLower(strings.TrimSpace(c.Tunnel.Provider))
	c.Tunnel.Binary = strings.TrimSpace(c.Tunnel.Binary)
	c.Tunnel.TokenFile = strings.TrimSpace(c.Tunnel.TokenFile)
	c.Tunnel.TokenEnv = strings.TrimSpace(c.Tunnel.TokenEnv)
	if c.Tunnel.Provider == "cloudflared" && c.Tunnel.Binary == "" {
		c.Tunnel.Binary = "cloudflared"
	}
	if strings.HasPrefix(c.Tunnel.TokenFile, "~/") || strings.HasPrefix(c.Tunnel.TokenFile, `~\`) {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			c.Tunnel.TokenFile = filepath.Join(home, c.Tunnel.TokenFile[2:])
		}
	}
	if c.Tunnel.TokenFile != "" && !filepath.IsAbs(c.Tunnel.TokenFile) && c.path != "" {
		c.Tunnel.TokenFile = filepath.Join(filepath.Dir(c.path), c.Tunnel.TokenFile)
	}
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.MaxSnapshotsPerGrant == 0 {
		c.MaxSnapshotsPerGrant = DefaultMaxSnapshotsPerGrant
	}
	for i := range c.AllowRedirectHosts {
		c.AllowRedirectHosts[i] = strings.TrimSpace(c.AllowRedirectHosts[i])
	}
	for i := range c.Workspaces {
		c.Workspaces[i].Name = strings.TrimSpace(c.Workspaces[i].Name)
		c.Workspaces[i].Path = strings.TrimSpace(c.Workspaces[i].Path)
		c.Workspaces[i].MaxPerm = Permission(strings.TrimSpace(string(c.Workspaces[i].MaxPerm)))
	}
}

func (c *Config) validatePublicURL(opts LoadOptions) error {
	raw := c.PublicURL
	if raw == "" {
		return fmt.Errorf("config: public_url is required")
	}
	if strings.ContainsAny(raw, "?#") {
		return fmt.Errorf("config: public_url must not contain a path, query, or fragment")
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Error embeds the raw URL, which may contain credentials; never
		// echo it back through logs or stderr.
		var urlErr *url.Error
		if errors.As(err, &urlErr) && urlErr.Err != nil {
			return fmt.Errorf("config: public_url is invalid: %v", urlErr.Err)
		}
		return fmt.Errorf("config: public_url is invalid")
	}
	if u.Scheme == "" || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("config: public_url must be an absolute URL with a host")
	}
	if u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("config: public_url must not contain userinfo, a path, query, or fragment")
	}
	scheme := strings.ToLower(u.Scheme)
	switch {
	case scheme == "https":
		return nil
	case scheme == "http" && opts.AllowHTTPPublicURL:
		if !isLoopbackListen(c.Listen) {
			return fmt.Errorf("config: public_url may use http:// only when listen is a loopback address (got %q)", c.Listen)
		}
		return nil
	default:
		return fmt.Errorf("config: public_url must use https:// (got scheme %q)", scheme)
	}
}

func isLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateListen(listen string) error {
	if listen == "" {
		return fmt.Errorf("config: listen is required")
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("config: listen %q must be host:port: %w", listen, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("config: listen %q has an invalid port", listen)
	}
	return nil
}

func validateRedirectHosts(hosts []string) error {
	for i, host := range hosts {
		switch {
		case host == "":
			return fmt.Errorf("config: allow_redirect_hosts[%d] is empty", i)
		case strings.Contains(host, "://"),
			strings.ContainsAny(host, "/\\?#"),
			strings.ContainsAny(host, " \t\r\n"):
			return fmt.Errorf("config: allow_redirect_hosts[%d] %q must be a bare host name", i, host)
		}
	}
	return nil
}

func validateDenyPatterns(patterns []string) error {
	for i, p := range patterns {
		if p == "" {
			return fmt.Errorf("config: deny_patterns[%d] is empty", i)
		}
		if _, err := path.Match(p, ""); err != nil {
			return fmt.Errorf("config: deny_patterns[%d] %q is not a valid glob: %w", i, p, err)
		}
	}
	return nil
}

func (c *Config) validateTunnel() error {
	switch c.Tunnel.Provider {
	case "", "none":
		return nil
	case "cloudflared":
		if c.Tunnel.TokenFile == "" && c.Tunnel.TokenEnv == "" {
			return fmt.Errorf("config: [tunnel] provider \"cloudflared\" requires token_file or token_env")
		}
		if c.Tunnel.TokenFile != "" && c.Tunnel.TokenEnv != "" {
			return fmt.Errorf("config: [tunnel] token_file and token_env are mutually exclusive")
		}
		if c.Tunnel.TokenEnv != "" && strings.ContainsAny(c.Tunnel.TokenEnv, "= \t\r\n") {
			return fmt.Errorf("config: [tunnel] token_env %q is not a valid environment variable name", c.Tunnel.TokenEnv)
		}
		return nil
	default:
		return fmt.Errorf("config: unsupported [tunnel] provider %q (want \"\", \"none\", or \"cloudflared\")", c.Tunnel.Provider)
	}
}

func validateWorkspaces(workspaces []Workspace, defaultMaxPerm Permission) error {
	seen := make(map[string]bool, len(workspaces))
	for i := range workspaces {
		w := &workspaces[i]
		if w.Name == "" {
			return fmt.Errorf("config: workspace[%d]: name is required", i)
		}
		if w.Name == "." || w.Name == ".." || !workspaceNameRE.MatchString(w.Name) {
			return fmt.Errorf("config: workspace[%d]: name %q must match [a-zA-Z0-9._-]+ and must not be '.' or '..'", i, w.Name)
		}
		if seen[w.Name] {
			return fmt.Errorf("config: workspace[%d]: duplicate name %q", i, w.Name)
		}
		seen[w.Name] = true

		if !filepath.IsAbs(w.Path) {
			return fmt.Errorf("config: workspace %q: path %q must be absolute", w.Name, w.Path)
		}
		info, err := os.Stat(w.Path)
		if err != nil {
			return fmt.Errorf("config: workspace %q: path %q is not accessible: %w", w.Name, w.Path, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("config: workspace %q: path %q is not a directory", w.Name, w.Path)
		}
		if w.MaxPerm == "" {
			w.MaxPerm = defaultMaxPerm
		}
		if !w.MaxPerm.Valid() {
			return fmt.Errorf("config: workspace %q: invalid max_perm %q (want read, write, or check)", w.Name, w.MaxPerm)
		}
		for _, check := range w.Checks {
			if !ws.KnownCheck(check) {
				return fmt.Errorf("config: workspace %q: unknown check %q", w.Name, check)
			}
		}
	}
	return nil
}

// Save validates nothing and writes the configuration atomically to path with
// mode 0600, creating parent directories with mode 0700.
func (c *Config) Save(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("config: resolve path %q: %w", path, err)
	}
	data, err := toml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: encode TOML: %w", err)
	}
	if err := writeFileAtomic(abs, data); err != nil {
		return err
	}
	c.path = abs
	return nil
}

// WriteExample writes the documented example config.toml to path atomically.
func WriteExample(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("config: resolve path %q: %w", path, err)
	}
	return writeFileAtomic(abs, []byte(ExampleTOML))
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("config: create directory %q: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".wsbridge-config-*.tmp")
	if err != nil {
		return fmt.Errorf("config: create temporary file in %q: %w", dir, err)
	}
	tmp := f.Name()
	defer func() {
		_ = os.Remove(tmp)
	}()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("config: chmod temporary file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("config: write temporary file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("config: sync temporary file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("config: close temporary file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("config: replace %q: %w", path, err)
	}
	return nil
}

// ExampleTOML is the initial config.toml written by "wsbridge init". It is
// syntactically valid; workspaces are selected dynamically from the working
// directory or via "wsbridge use <dir>" unless [[workspace]] blocks are added.
const ExampleTOML = `# wsbridge configuration
#
# public_url MUST be the stable HTTPS origin of your tunnel and must not
# contain a trailing slash or a path (for example: https://my-box.tail1234.ts.net).

public_url = "https://my-box.tail1234.ts.net"

# Local listen address. Keep it on the loopback interface; the public tunnel
# forwards to this address.
listen = "127.0.0.1:8787"

# Directory for wsbridge.db, audit.jsonl, snapshots/, and active workspace state.
# Leave empty to use the directory that contains this file.
data_dir = ""

# Optional local permission ceiling ("read", "write", or "check").
# Leave omitted to allow full access ("check") and govern each connection's
# permission from the OAuth consent page.
# max_perm = "check"

# Extra OAuth redirect hosts (exact host names added to the built-in allowlist).
allow_redirect_hosts = []

# Extra sensitive-file globs appended to the built-in denylist.
# .git and .ssh are always blocked and cannot be re-enabled.
deny_patterns = []

# Maximum number of pre-write snapshots kept per Grant.
max_snapshots_per_grant = 20

# Optional managed tunnel subprocess. Leave disabled if you run cloudflared
# or another reverse proxy separately.
# [tunnel]
# provider = "cloudflared"
# token_file = "cloudflared-token"
# # or: token_env = "CLOUDFLARE_TUNNEL_TOKEN"

# Workspaces are optional. By default, "wsbridge serve" exposes the current
# working directory and "wsbridge use <dir>" hot-switches the active directory
# without disconnecting remote MCP clients.
#
# Uncomment to pin static workspaces instead:
# [[workspace]]
# name = "myapp"
# path = "/home/me/code/myapp"
`
