// Package tunnel implements the public-connectivity self-test used by
// "wsbridge doctor".
package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"wsbridge/internal/config"
	"wsbridge/internal/oauth"
)

// Level is the severity of a doctor check.
type Level int

const (
	Pass Level = iota
	Warn
	Fail
)

func (l Level) String() string {
	switch l {
	case Pass:
		return "PASS"
	case Warn:
		return "WARN"
	default:
		return "FAIL"
	}
}

// Check is one diagnostic result.
type Check struct {
	Name   string
	Level  Level
	Detail string
}

// Failed reports whether any check is critical.
func Failed(checks []Check) bool {
	for _, c := range checks {
		if c.Level == Fail {
			return true
		}
	}
	return false
}

// Count returns the number of checks at level.
func Count(checks []Check, level Level) int {
	n := 0
	for _, c := range checks {
		if c.Level == level {
			n++
		}
	}
	return n
}

// Options configures a doctor run.
type Options struct {
	Config  *config.Config
	DataDir string
	// Client must not follow redirects. A default is used when nil.
	Client  *http.Client
	Timeout time.Duration
	// LookPath overrides executable discovery in tests.
	LookPath func(string) (string, error)
}

const maxDoctorBody = 256 << 10

// Run performs local and public checks. It never panics on network failure;
// every problem is reported as a Check.
func Run(ctx context.Context, opts Options) []Check {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.LookPath == nil {
		opts.LookPath = exec.LookPath
	}
	if opts.Client == nil {
		opts.Client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	checks := localChecks(opts)
	if opts.Config == nil {
		return checks
	}
	return append(checks, networkChecks(ctx, opts)...)
}

func localChecks(opts Options) []Check {
	checks := []Check{dataDirCheck(opts)}
	checks = append(checks, databaseCheck(opts)...)
	if opts.Config != nil {
		for _, ws := range opts.Config.Workspaces {
			checks = append(checks, workspaceCheck(ws))
		}
	}
	if _, err := opts.LookPath("rg"); err == nil {
		checks = append(checks, Check{Name: "ripgrep", Level: Pass, Detail: "rg found; searches use ripgrep"})
	} else {
		checks = append(checks, Check{Name: "ripgrep", Level: Warn,
			Detail: "rg not found; search_code uses the slower pure-Go fallback"})
	}
	return checks
}

func dataDirCheck(opts Options) Check {
	if opts.DataDir == "" {
		return Check{Name: "data directory", Level: Fail, Detail: "data_dir is not configured"}
	}
	info, err := os.Stat(opts.DataDir)
	if err != nil {
		return Check{Name: "data directory", Level: Fail, Detail: fmt.Sprintf("%s is not accessible: %v", opts.DataDir, err)}
	}
	if !info.IsDir() {
		return Check{Name: "data directory", Level: Fail, Detail: fmt.Sprintf("%s is not a directory", opts.DataDir)}
	}
	probe, err := os.CreateTemp(opts.DataDir, ".wsbridge-doctor-*")
	if err != nil {
		return Check{Name: "data directory", Level: Fail, Detail: fmt.Sprintf("%s is not writable: %v", opts.DataDir, err)}
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return Check{Name: "data directory", Level: Warn,
			Detail: fmt.Sprintf("%s mode is %04o; 0700 is recommended", opts.DataDir, info.Mode().Perm())}
	}
	return Check{Name: "data directory", Level: Pass, Detail: opts.DataDir + " is writable"}
}

func databaseCheck(opts Options) []Check {
	if opts.DataDir == "" {
		return nil
	}
	path := filepath.Join(opts.DataDir, "wsbridge.db")
	meta, err := oauth.PeekMeta(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return []Check{{Name: "oauth database", Level: Fail,
			Detail: "wsbridge.db does not exist; run \"wsbridge passwd\" first"}}
	case errors.Is(err, bolt.ErrTimeout):
		return []Check{{Name: "oauth database", Level: Warn,
			Detail: "database is locked by a running wsbridge serve; passphrase/issuer checks skipped"}}
	case err != nil:
		return []Check{{Name: "oauth database", Level: Fail, Detail: err.Error()}}
	}
	var checks []Check
	if !meta.AdminPassphraseSet {
		checks = append(checks, Check{Name: "administrator passphrase", Level: Fail,
			Detail: "not set; run \"wsbridge passwd\""})
	} else {
		checks = append(checks, Check{Name: "administrator passphrase", Level: Pass, Detail: "argon2id hash is set"})
	}
	if opts.Config != nil && meta.Issuer != opts.Config.PublicURL {
		checks = append(checks, Check{Name: "stored issuer", Level: Warn,
			Detail: fmt.Sprintf("database issuer %q differs from public_url %q; the next serve will revoke all grants",
				meta.Issuer, opts.Config.PublicURL)})
	}
	return checks
}

func workspaceCheck(ws config.Workspace) Check {
	name := "workspace " + ws.Name
	info, err := os.Stat(ws.Path)
	if err != nil {
		return Check{Name: name, Level: Fail, Detail: fmt.Sprintf("%s is not accessible: %v", ws.Path, err)}
	}
	if !info.IsDir() {
		return Check{Name: name, Level: Fail, Detail: fmt.Sprintf("%s is not a directory", ws.Path)}
	}
	detail := fmt.Sprintf("%s (max_perm=%s)", ws.Path, ws.MaxPerm)
	if _, err := os.Stat(filepath.Join(ws.Path, ".git")); err != nil {
		return Check{Name: name, Level: Warn,
			Detail: detail + "; not a Git repository, so pre-write snapshots are the only rollback path"}
	}
	return Check{Name: name, Level: Pass, Detail: detail + "; Git repository detected"}
}

type doctorResponse struct {
	status int
	header http.Header
	body   []byte
}

func doRequest(ctx context.Context, opts Options, method, rawURL string, payload []byte) (*doctorResponse, error) {
	reqCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := opts.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDoctorBody))
	if err != nil {
		return nil, err
	}
	return &doctorResponse{status: resp.StatusCode, header: resp.Header.Clone(), body: data}, nil
}

func redirectFailure(name string, resp *doctorResponse) Check {
	location := resp.header.Get("Location")
	return Check{Name: name, Level: Fail,
		Detail: fmt.Sprintf("unexpected %d redirect to %q; cloud clients drop the Authorization header on redirects",
			resp.status, location)}
}

func networkChecks(ctx context.Context, opts Options) []Check {
	base := strings.TrimRight(opts.Config.PublicURL, "/")
	prmURL := base + "/.well-known/oauth-protected-resource/mcp"
	asURL := base + "/.well-known/oauth-authorization-server"

	var checks []Check
	checks = append(checks, checkPRM(ctx, opts, prmURL, base))
	checks = append(checks, checkASMetadata(ctx, opts, asURL, base))
	for _, path := range []string{"/mcp", "/mcp/"} {
		checks = append(checks, checkMCPUnauthorized(ctx, opts, base+path, prmURL))
	}
	checks = append(checks, checkDCR(ctx, opts, base+"/oauth/register"))
	return checks
}

func checkPRM(ctx context.Context, opts Options, url, base string) Check {
	const name = "public PRM"
	resp, err := doRequest(ctx, opts, http.MethodGet, url, nil)
	if err != nil {
		return Check{Name: name, Level: Fail, Detail: "request failed: " + err.Error()}
	}
	if resp.status >= 300 && resp.status < 400 {
		return redirectFailure(name, resp)
	}
	if resp.status != http.StatusOK {
		return Check{Name: name, Level: Fail,
			Detail: fmt.Sprintf("GET %s returned %d, want 200", url, resp.status)}
	}
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(resp.body, &prm); err != nil {
		return Check{Name: name, Level: Fail, Detail: "response is not valid JSON"}
	}
	wantResource := base + "/mcp"
	if prm.Resource != wantResource {
		return Check{Name: name, Level: Fail,
			Detail: fmt.Sprintf("resource = %q, want %q", prm.Resource, wantResource)}
	}
	found := false
	for _, server := range prm.AuthorizationServers {
		if strings.TrimRight(server, "/") == base {
			found = true
		}
	}
	if !found {
		return Check{Name: name, Level: Fail,
			Detail: fmt.Sprintf("authorization_servers = %v, want it to contain %q", prm.AuthorizationServers, base)}
	}
	return Check{Name: name, Level: Pass, Detail: "resource and authorization_servers match public_url"}
}

func checkASMetadata(ctx context.Context, opts Options, url, base string) Check {
	const name = "public AS metadata"
	resp, err := doRequest(ctx, opts, http.MethodGet, url, nil)
	if err != nil {
		return Check{Name: name, Level: Fail, Detail: "request failed: " + err.Error()}
	}
	if resp.status >= 300 && resp.status < 400 {
		return redirectFailure(name, resp)
	}
	if resp.status != http.StatusOK {
		return Check{Name: name, Level: Fail,
			Detail: fmt.Sprintf("GET %s returned %d, want 200", url, resp.status)}
	}
	var meta struct {
		Issuer                    string   `json:"issuer"`
		TokenEndpoint             string   `json:"token_endpoint"`
		CodeChallengeMethods      []string `json:"code_challenge_methods_supported"`
		ScopesSupported           []string `json:"scopes_supported"`
		ClientIDMetadataSupported bool     `json:"client_id_metadata_document_supported"`
	}
	if err := json.Unmarshal(resp.body, &meta); err != nil {
		return Check{Name: name, Level: Fail, Detail: "response is not valid JSON"}
	}
	if meta.Issuer != base {
		return Check{Name: name, Level: Fail, Detail: fmt.Sprintf("issuer = %q, want %q", meta.Issuer, base)}
	}
	if meta.TokenEndpoint != base+"/oauth/token" {
		return Check{Name: name, Level: Fail,
			Detail: fmt.Sprintf("token_endpoint = %q, want %q", meta.TokenEndpoint, base+"/oauth/token")}
	}
	if !contains(meta.CodeChallengeMethods, "S256") {
		return Check{Name: name, Level: Fail, Detail: "code_challenge_methods_supported does not include S256"}
	}
	if !contains(meta.ScopesSupported, "offline_access") {
		return Check{Name: name, Level: Fail, Detail: "scopes_supported does not include offline_access"}
	}
	if meta.ClientIDMetadataSupported {
		return Check{Name: name, Level: Warn,
			Detail: "client_id_metadata_document_supported is true, but this build only serves DCR clients"}
	}
	return Check{Name: name, Level: Pass, Detail: "issuer, token endpoint, S256, and offline_access are correct"}
}

func checkMCPUnauthorized(ctx context.Context, opts Options, url, prmURL string) Check {
	name := "public " + strings.TrimPrefix(url, strings.TrimRight(opts.Config.PublicURL, "/"))
	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	resp, err := doRequest(ctx, opts, http.MethodPost, url, payload)
	if err != nil {
		return Check{Name: name, Level: Fail, Detail: "request failed: " + err.Error()}
	}
	if resp.status >= 300 && resp.status < 400 {
		return redirectFailure(name, resp)
	}
	if resp.status != http.StatusUnauthorized {
		return Check{Name: name, Level: Fail,
			Detail: fmt.Sprintf("POST %s without a token returned %d, want 401", url, resp.status)}
	}
	www := resp.header.Get("WWW-Authenticate")
	if !strings.Contains(www, `resource_metadata="`+prmURL+`"`) {
		return Check{Name: name, Level: Fail,
			Detail: fmt.Sprintf("WWW-Authenticate = %q, want resource_metadata=%q", www, prmURL)}
	}
	if !bytes.Contains(resp.body, []byte(`"invalid_token"`)) {
		return Check{Name: name, Level: Fail, Detail: "401 body does not contain invalid_token"}
	}
	return Check{Name: name, Level: Pass, Detail: "401 with discovery metadata and no redirect"}
}

func checkDCR(ctx context.Context, opts Options, url string) Check {
	const name = "public DCR"
	// An empty registration is rejected without creating a client.
	resp, err := doRequest(ctx, opts, http.MethodPost, url, []byte(`{}`))
	if err != nil {
		return Check{Name: name, Level: Fail, Detail: "request failed: " + err.Error()}
	}
	if resp.status >= 300 && resp.status < 400 {
		return redirectFailure(name, resp)
	}
	var oauthErr struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(resp.body, &oauthErr); err != nil {
		return Check{Name: name, Level: Fail, Detail: "endpoint did not return an OAuth JSON error"}
	}
	if resp.status != http.StatusBadRequest || oauthErr.Error != "invalid_redirect_uri" {
		return Check{Name: name, Level: Fail,
			Detail: fmt.Sprintf("probe returned %d %q, want 400 invalid_redirect_uri", resp.status, oauthErr.Error)}
	}
	return Check{Name: name, Level: Pass, Detail: "DCR is reachable and validates redirect_uris"}
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
