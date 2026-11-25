// Package e2e exercises the complete wsbridge OAuth + MCP flow against an
// in-process HTTP server, as specified in docs/development.md section 3.3.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/RolinShmily/wsbridge-mcp/internal/audit"
	"github.com/RolinShmily/wsbridge-mcp/internal/mcpsrv"
	"github.com/RolinShmily/wsbridge-mcp/internal/oauth"
	"github.com/RolinShmily/wsbridge-mcp/internal/ws"
)

const testPassphrase = "e2e-administrator-passphrase"

func newStack(t *testing.T) (baseURL, issuer, clientID, verifier, code, accessToken, refreshToken string) {
	t.Helper()
	dataDir := t.TempDir()
	wsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(wsDir, "seed.txt"), []byte("seed content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("git"); err == nil {
		cmd := exec.Command("git", "init", "-q")
		cmd.Dir = wsDir
		if err := cmd.Run(); err != nil {
			t.Fatalf("git init: %v", err)
		}
	}

	mgr, err := ws.NewManager([]ws.WorkspaceConfig{{
		Name: "app", Path: wsDir, MaxPerm: ws.PermCheck, Checks: []string{"git_status"},
	}}, ws.ManagerOptions{DataDir: dataDir, RipgrepPath: "none"})
	if err != nil {
		t.Fatalf("ws.NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })

	mux := http.NewServeMux()
	httpServer := httptest.NewUnstartedServer(mux)
	issuer = "http://" + httpServer.Listener.Addr().String()

	store, err := oauth.OpenStore(filepath.Join(dataDir, "wsbridge.db"), oauth.StoreOptions{Issuer: issuer})
	if err != nil {
		t.Fatalf("oauth.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	hash, err := oauth.HashAdminPassphrase(testPassphrase, oauth.Argon2Params{
		Memory: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetAdminHash(hash); err != nil {
		t.Fatal(err)
	}
	auditLogger, err := audit.Open(filepath.Join(dataDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auditLogger.Close() })
	auth, err := oauth.New(oauth.Config{
		Issuer: issuer,
		Store:  store,
		Audit:  auditLogger,
		Workspaces: []oauth.WorkspaceChoice{
			{Name: "app", Path: wsDir, MaxPerm: ws.PermCheck, Checks: []string{"git_status"}},
		},
	})
	if err != nil {
		t.Fatalf("oauth.New: %v", err)
	}
	auth.Mount(mux)
	mcpServer, err := mcpsrv.New(mcpsrv.Options{
		Manager: mgr,
		Version: "e2e",
		Audit:   auditLogger,
		Scope:   mcpsrv.GrantScope(mgr),
		Auth: &mcpsrv.AuthConfig{
			Verifier:            store,
			ResourceURL:         auth.ResourceURL(),
			ResourceMetadataURL: auth.ResourceMetadataURL(),
		},
	})
	if err != nil {
		t.Fatalf("mcpsrv.New: %v", err)
	}
	mcpServer.Mount(mux)
	httpServer.Start()
	t.Cleanup(httpServer.Close)
	baseURL = httpServer.URL

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// 1. Unauthenticated /mcp must produce the discovery 401.
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		req, err := http.NewRequest(method, baseURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s /mcp status = %d, want 401: %s", method, resp.StatusCode, raw)
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			t.Fatalf("%s /mcp redirected to %q", method, loc)
		}
		www := resp.Header.Get("WWW-Authenticate")
		if !strings.Contains(www, "resource_metadata=") {
			t.Fatalf("WWW-Authenticate = %q", www)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp/", strings.NewReader(`{}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/mcp/ status = %d, want 401", resp.StatusCode)
	}

	// 2. Protected resource metadata.
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	www := resp.Header.Get("WWW-Authenticate")
	resp.Body.Close()
	m := regexp.MustCompile(`resource_metadata="([^"]+)"`).FindStringSubmatch(www)
	if len(m) != 2 {
		t.Fatalf("WWW-Authenticate has no resource_metadata: %q", www)
	}
	resp, err = noRedirect.Get(m[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(resp.Body).Decode(&prm); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if prm.Resource != issuer+"/mcp" {
		t.Fatalf("resource = %q, want %q", prm.Resource, issuer+"/mcp")
	}
	if len(prm.AuthorizationServers) != 1 || prm.AuthorizationServers[0] != issuer {
		t.Fatalf("authorization_servers = %v", prm.AuthorizationServers)
	}

	// 3. Authorization server metadata.
	resp, err = noRedirect.Get(prm.AuthorizationServers[0] + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for key, want := range map[string]string{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/oauth/authorize",
		"token_endpoint":         issuer + "/oauth/token",
		"registration_endpoint":  issuer + "/oauth/register",
		"revocation_endpoint":    issuer + "/oauth/revoke",
	} {
		if meta[key] != want {
			t.Errorf("%s = %v, want %q", key, meta[key], want)
		}
	}
	if !containsString(meta["code_challenge_methods_supported"], "S256") {
		t.Errorf("code_challenge_methods_supported = %v", meta["code_challenge_methods_supported"])
	}
	if !containsString(meta["scopes_supported"], "offline_access") {
		t.Errorf("scopes_supported = %v", meta["scopes_supported"])
	}

	// 4. Dynamic client registration with a loopback callback.
	redirectURI := "http://127.0.0.1:19999/callback"
	regBody, _ := json.Marshal(map[string]any{
		"client_name":                "E2E Client",
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	resp, err = noRedirect.Post(issuer+"/oauth/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	var registration struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&registration); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || registration.ClientID == "" {
		t.Fatalf("registration status = %d client_id = %q", resp.StatusCode, registration.ClientID)
	}
	clientID = registration.ClientID

	// 5. PKCE authorization with consent.
	verifier = randomVerifier(t)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := "e2e-state"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"scope":                 {"mcp:tools offline_access"},
		"resource":              {issuer + "/mcp"},
	}
	resp, err = noRedirect.Get(issuer + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize GET status = %d: %s", resp.StatusCode, page)
	}
	authReq := regexp.MustCompile(`name="auth_req_id" value="([^"]+)"`).FindSubmatch(page)
	csrf := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindSubmatch(page)
	if authReq == nil || csrf == nil {
		t.Fatalf("consent page missing hidden fields")
	}
	resp, err = noRedirect.PostForm(issuer+"/oauth/authorize", url.Values{
		"auth_req_id": {string(authReq[1])},
		"csrf_token":  {string(csrf[1])},
		"action":      {"approve"},
		"workspaces":  {"app"},
		"permission":  {"check"},
		"ttl_hours":   {"1"},
		"passphrase":  {testPassphrase},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize POST status = %d", resp.StatusCode)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := location.Query().Get("state"); got != state {
		t.Errorf("state = %q", got)
	}
	if got := location.Query().Get("iss"); got != issuer {
		t.Errorf("iss = %q", got)
	}
	code = location.Query().Get("code")
	if code == "" {
		t.Fatal("authorization redirect has no code")
	}

	// 6. Code exchange.
	resp, err = noRedirect.PostForm(issuer+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
		"resource":      {issuer + "/mcp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("token status = %d tokens = %+v", resp.StatusCode, tokens)
	}
	accessToken, refreshToken = tokens.AccessToken, tokens.RefreshToken
	return baseURL, issuer, clientID, verifier, code, accessToken, refreshToken
}

func randomVerifier(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func containsString(v any, want string) bool {
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if s, ok := item.(string); ok && s == want {
			return true
		}
	}
	return false
}

type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(clone)
}

func connectMCP(t *testing.T, baseURL, token string) *mcp.ClientSession {
	t.Helper()
	httpClient := &http.Client{Transport: &bearerTransport{base: http.DefaultTransport, token: token}}
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-client", Version: "1"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             baseURL + "/mcp",
		HTTPClient:           httpClient,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("MCP connect: %v", err)
	}
	return session
}

func callTool(t *testing.T, session *mcp.ClientSession, name string, args any) string {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("%s returned an error: %+v", name, res.Content)
	}
	if len(res.Content) == 0 {
		t.Fatalf("%s returned no content", name)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("%s content type = %T", name, res.Content[0])
	}
	return text.Text
}

func TestFullOAuthAndMCPFlow(t *testing.T) {
	baseURL, issuer, clientID, _, _, accessToken, refreshToken := newStack(t)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// 7. Full MCP tool surface with the bearer token.
	session := connectMCP(t, baseURL, accessToken)
	list, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(list.Tools) != 7 {
		t.Errorf("tools = %d, want 7", len(list.Tools))
	}
	if text := callTool(t, session, "list_workspaces", map[string]any{}); !strings.Contains(text, "name: app") {
		t.Errorf("list_workspaces = %q", text)
	}
	if text := callTool(t, session, "get_file_tree", map[string]any{}); !strings.Contains(text, "seed.txt") {
		t.Errorf("get_file_tree = %q", text)
	}
	if text := callTool(t, session, "write_file", map[string]any{"path": "new.txt", "content": "created by e2e\n"}); !strings.Contains(text, "SHA256:") {
		t.Errorf("write_file = %q", text)
	}
	if text := callTool(t, session, "read_file", map[string]any{"path": "new.txt"}); !strings.Contains(text, "created by e2e") {
		t.Errorf("read_file = %q", text)
	}
	if text := callTool(t, session, "edit_file", map[string]any{
		"path":  "new.txt",
		"edits": []map[string]any{{"old_text": "created", "new_text": "edited"}},
	}); !strings.Contains(text, "+edited by e2e") {
		t.Errorf("edit_file = %q", text)
	}
	if text := callTool(t, session, "search_code", map[string]any{"query": "edited"}); !strings.Contains(text, "new.txt:1:") {
		t.Errorf("search_code = %q", text)
	}
	if _, err := exec.LookPath("git"); err == nil {
		if text := callTool(t, session, "run_check", map[string]any{"name": "git_status"}); !strings.Contains(text, "Exit: 0") {
			t.Errorf("run_check = %q", text)
		}
	} else {
		t.Log("git is not installed; run_check was verified in unit tests")
	}

	// 8. Refresh rotation: the new access token works, the old one gets 401.
	resp, err := noRedirect.PostForm(issuer+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	})
	if err != nil {
		t.Fatal(err)
	}
	var rotated struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rotated); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || rotated.AccessToken == "" || rotated.AccessToken == accessToken {
		t.Fatalf("refresh status = %d token = %q", resp.StatusCode, rotated.AccessToken)
	}
	session2 := connectMCP(t, baseURL, rotated.AccessToken)
	if text := callTool(t, session2, "read_file", map[string]any{"path": "new.txt"}); !strings.Contains(text, "edited by e2e") {
		t.Errorf("read_file with rotated token = %q", text)
	}
	_ = session2.Close()

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("old access token status = %d, want 401", resp.StatusCode)
	}

	// 9. Revoke the grant and confirm the rotated token is rejected.
	resp, err = noRedirect.PostForm(issuer+"/oauth/revoke", url.Values{"token": {rotated.RefreshToken}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+rotated.AccessToken)
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked token status = %d, want 401", resp.StatusCode)
	}

	_ = session.Close()
}

func TestRefreshReplayAfterGraceRevokesGrant(t *testing.T) {
	// Covered with an injected clock in internal/oauth; this asserts the wire
	// behavior of a replayed authorization code at the e2e boundary.
	baseURL, issuer, clientID, verifier, code, accessToken, _ := newStack(t)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := noRedirect.PostForm(issuer+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:19999/callback"},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	var replay struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&replay); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || replay.Error != "invalid_grant" {
		t.Fatalf("code replay status = %d error = %q", resp.StatusCode, replay.Error)
	}
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("access token after code replay status = %d, want 401", resp.StatusCode)
	}
}
