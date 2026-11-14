package oauth_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"wsbridge/internal/audit"
	"wsbridge/internal/oauth"
	"wsbridge/internal/ws"

	bolt "go.etcd.io/bbolt"
)

const (
	testIssuer = "https://bridge.example.com"
	testPass   = "a-very-long-test-passphrase"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type testEnv struct {
	t         *testing.T
	server    *httptest.Server
	client    *http.Client
	store     *oauth.Store
	auth      *oauth.Server
	clock     *testClock
	auditPath string
	redirect  string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	clock := &testClock{t: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
	store, err := oauth.OpenStore(filepath.Join(dir, "wsbridge.db"), oauth.StoreOptions{
		Issuer: testIssuer, Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	hash, err := oauth.HashAdminPassphrase(testPass, oauth.Argon2Params{
		Memory: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32,
	})
	if err != nil {
		t.Fatalf("HashAdminPassphrase: %v", err)
	}
	if err := store.SetAdminHash(hash); err != nil {
		t.Fatalf("SetAdminHash: %v", err)
	}
	auditPath := filepath.Join(dir, "audit.jsonl")
	auditLogger, err := audit.Open(auditPath)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = auditLogger.Close() })
	auth, err := oauth.New(oauth.Config{
		Issuer: testIssuer,
		Store:  store,
		Audit:  auditLogger,
		Workspaces: []oauth.WorkspaceChoice{
			{Name: "app", Path: "/tmp/app", MaxPerm: ws.PermCheck, Checks: []string{"git_status"}},
		},
		Now:    clock.Now,
		Argon2: oauth.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32},
	})
	if err != nil {
		t.Fatalf("oauth.New: %v", err)
	}
	server := httptest.NewServer(auth.Handler())
	t.Cleanup(server.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return &testEnv{
		t: t, server: server, client: client, store: store, auth: auth,
		clock: clock, auditPath: auditPath, redirect: "https://claude.ai/api/mcp/auth_callback",
	}
}

func (e *testEnv) registerClient() string {
	e.t.Helper()
	body := fmt.Sprintf(`{"client_name":"Claude","redirect_uris":[%q],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}`, e.redirect)
	resp, err := e.client.Post(e.server.URL+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		e.t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		e.t.Fatalf("register status = %d body = %s", resp.StatusCode, raw)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		e.t.Fatalf("decode registration: %v", err)
	}
	if !strings.HasPrefix(out.ClientID, "wsb_cli_") {
		e.t.Fatalf("client_id = %q", out.ClientID)
	}
	return out.ClientID
}

func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

var (
	authReqRE = regexp.MustCompile(`name="auth_req_id" value="([^"]+)"`)
	csrfRE    = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
)

func (e *testEnv) authorizeForm(clientID, challenge string) (id, csrf string) {
	e.t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {e.redirect},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"client-state-123"},
		"scope":                 {"mcp:tools offline_access"},
		"resource":              {testIssuer + "/mcp"},
	}
	resp, err := e.client.Get(e.server.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		e.t.Fatalf("authorize GET: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("authorize GET status = %d body = %s", resp.StatusCode, raw)
	}
	idMatch, csrfMatch := authReqRE.FindSubmatch(raw), csrfRE.FindSubmatch(raw)
	if idMatch == nil || csrfMatch == nil {
		e.t.Fatalf("authorize page missing hidden fields: %s", raw)
	}
	return string(idMatch[1]), string(csrfMatch[1])
}

func (e *testEnv) approve(id, csrf, passphrase string) *http.Response {
	e.t.Helper()
	resp, err := e.client.PostForm(e.server.URL+"/oauth/authorize", url.Values{
		"auth_req_id": {id},
		"csrf_token":  {csrf},
		"action":      {"approve"},
		"workspaces":  {"app"},
		"permission":  {"read"},
		"ttl_hours":   {"1"},
		"passphrase":  {passphrase},
	})
	if err != nil {
		e.t.Fatalf("authorize POST: %v", err)
	}
	return resp
}

func (e *testEnv) obtainCode() (clientID, verifier, code string) {
	e.t.Helper()
	clientID = e.registerClient()
	verifier, challenge := pkcePair(e.t)
	id, csrf := e.authorizeForm(clientID, challenge)
	resp := e.approve(id, csrf, testPass)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		raw, _ := io.ReadAll(resp.Body)
		e.t.Fatalf("approve status = %d body = %s", resp.StatusCode, raw)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		e.t.Fatalf("Location: %v", err)
	}
	q := loc.Query()
	if got := q.Get("iss"); got != testIssuer {
		e.t.Errorf("iss = %q, want %q", got, testIssuer)
	}
	if got := q.Get("state"); got != "client-state-123" {
		e.t.Errorf("state = %q", got)
	}
	code = q.Get("code")
	if code == "" {
		e.t.Fatal("redirect has no code")
	}
	return clientID, verifier, code
}

type tokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
	Description  string `json:"error_description"`
}

func (e *testEnv) exchange(clientID, verifier, code string) *http.Response {
	e.t.Helper()
	resp, err := e.client.PostForm(e.server.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {e.redirect},
		"client_id":     {clientID},
		"code_verifier": {verifier},
		"resource":      {testIssuer + "/mcp"},
	})
	if err != nil {
		e.t.Fatalf("token POST: %v", err)
	}
	return resp
}

func decodeToken(t *testing.T, resp *http.Response) tokenJSON {
	t.Helper()
	defer resp.Body.Close()
	var out tokenJSON
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return out
}

func TestMetadataEndpoints(t *testing.T) {
	env := newTestEnv(t)
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		resp, err := env.client.Get(env.server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		var prm struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
			ScopesSupported      []string `json:"scopes_supported"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&prm); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 || prm.Resource != testIssuer+"/mcp" {
			t.Errorf("%s: status=%d resource=%q", path, resp.StatusCode, prm.Resource)
		}
		if len(prm.AuthorizationServers) != 1 || prm.AuthorizationServers[0] != testIssuer {
			t.Errorf("%s: authorization_servers = %v", path, prm.AuthorizationServers)
		}
	}
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		resp, err := env.client.Get(env.server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		var meta map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		if meta["issuer"] != testIssuer {
			t.Errorf("%s: issuer = %v", path, meta["issuer"])
		}
		if meta["token_endpoint"] != testIssuer+"/oauth/token" {
			t.Errorf("%s: token_endpoint = %v", path, meta["token_endpoint"])
		}
		if meta["authorization_response_iss_parameter_supported"] != true {
			t.Errorf("%s: iss parameter support missing", path)
		}
	}
}

func TestRegisterValidation(t *testing.T) {
	env := newTestEnv(t)
	tests := []struct {
		name string
		body string
		want string
	}{
		{"empty redirects", `{"redirect_uris":[]}`, "invalid_redirect_uri"},
		{"too many redirects", `{"redirect_uris":["https://claude.ai/a","https://claude.ai/b","https://claude.ai/c","https://claude.ai/d","https://claude.ai/e","https://claude.ai/f","https://claude.ai/g","https://claude.ai/h","https://claude.ai/i","https://claude.ai/j","https://claude.ai/k"]}`, "invalid_redirect_uri"},
		{"fragment", `{"redirect_uris":["https://claude.ai/cb#frag"]}`, "invalid_redirect_uri"},
		{"host not allowed", `{"redirect_uris":["https://evil.example/cb"]}`, "invalid_redirect_uri"},
		{"http non-loopback", `{"redirect_uris":["http://claude.ai/cb"]}`, "invalid_redirect_uri"},
		{"client auth method", `{"redirect_uris":["https://claude.ai/cb"],"token_endpoint_auth_method":"client_secret_basic"}`, "invalid_client_metadata"},
		{"bad grant type", `{"redirect_uris":["https://claude.ai/cb"],"grant_types":["implicit"]}`, "invalid_client_metadata"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := env.client.Post(env.server.URL+"/oauth/register", "application/json", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var out tokenJSON
			_ = json.NewDecoder(resp.Body).Decode(&out)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
			if out.Error != tc.want {
				t.Errorf("error = %q, want %q", out.Error, tc.want)
			}
		})
	}
}

func TestAuthorizeRejectsInvalidRequestsWithoutRedirect(t *testing.T) {
	env := newTestEnv(t)
	clientID := env.registerClient()
	_, challenge := pkcePair(t)
	base := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {env.redirect},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	tests := []struct {
		name   string
		mutate func(url.Values)
		want   string
	}{
		{"missing client", func(v url.Values) { v.Del("client_id") }, "invalid_request"},
		{"unknown client", func(v url.Values) { v.Set("client_id", "wsb_cli_nope") }, "invalid_request"},
		{"unregistered redirect", func(v url.Values) { v.Set("redirect_uri", "https://claude.ai/other") }, "invalid_request"},
		{"redirect with extra query", func(v url.Values) { v.Set("redirect_uri", env.redirect+"?extra=1") }, "invalid_request"},
		{"redirect trailing slash", func(v url.Values) { v.Set("redirect_uri", env.redirect+"/") }, "invalid_request"},
		{"bad redirect host", func(v url.Values) { v.Set("redirect_uri", "https://evil.example/cb") }, "invalid_request"},
		{"plain PKCE", func(v url.Values) { v.Set("code_challenge_method", "plain") }, "invalid_request"},
		{"short challenge", func(v url.Values) { v.Set("code_challenge", "short") }, "invalid_request"},
		{"wrong response type", func(v url.Values) { v.Set("response_type", "token") }, "invalid_request"},
		{"wrong resource", func(v url.Values) { v.Set("resource", "https://other.example/mcp") }, "invalid_target"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{}
			for k, v := range base {
				q[k] = append([]string(nil), v...)
			}
			tc.mutate(q)
			resp, err := env.client.Get(env.server.URL + "/oauth/authorize?" + q.Encode())
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
			if loc := resp.Header.Get("Location"); loc != "" {
				t.Errorf("unexpected redirect to %q", loc)
			}
			if !strings.Contains(string(raw), tc.want) {
				t.Errorf("body does not mention %q: %s", tc.want, raw)
			}
		})
	}
}

func TestFullCodeFlowAndRefreshRotation(t *testing.T) {
	env := newTestEnv(t)
	clientID, verifier, code := env.obtainCode()

	resp := env.exchange(clientID, verifier, code)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("token exchange status = %d body = %s", resp.StatusCode, raw)
	}
	tok := decodeToken(t, resp)
	if tok.TokenType != "Bearer" || tok.ExpiresIn != 3600 || tok.RefreshToken == "" {
		t.Fatalf("token response = %+v", tok)
	}
	if tok.Scope != "mcp:tools offline_access" {
		t.Errorf("scope = %q", tok.Scope)
	}
	principal, err := env.store.VerifyAccessToken(tok.AccessToken, testIssuer+"/mcp")
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if perm := principal.Workspaces["app"]; perm != ws.PermRead {
		t.Errorf("grant permission = %v, want read", perm)
	}

	// Wrong resource binding must not verify.
	if _, err := env.store.VerifyAccessToken(tok.AccessToken, "https://other.example/mcp"); err == nil {
		t.Error("token verified for the wrong resource")
	}

	refresh := func(token string) (*http.Response, tokenJSON) {
		t.Helper()
		resp, err := env.client.PostForm(env.server.URL+"/oauth/token", url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {token},
			"client_id":     {clientID},
		})
		if err != nil {
			t.Fatal(err)
		}
		return resp, decodeToken(t, resp)
	}
	resp, first := refresh(tok.RefreshToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first refresh status = %d error = %s", resp.StatusCode, first.Error)
	}
	if first.AccessToken == tok.AccessToken || first.RefreshToken == tok.RefreshToken {
		t.Fatal("refresh did not rotate tokens")
	}
	if _, err := env.store.VerifyAccessToken(tok.AccessToken, testIssuer+"/mcp"); err == nil {
		t.Error("old access token still valid after rotation")
	}

	// Within the grace window the same old refresh token returns the same pair.
	resp, again := refresh(tok.RefreshToken)
	if resp.StatusCode != http.StatusOK || again.AccessToken != first.AccessToken || again.RefreshToken != first.RefreshToken {
		t.Fatalf("grace refresh status = %d tokens differ", resp.StatusCode)
	}

	// Outside the grace window the old token is treated as stolen and the
	// whole grant is revoked.
	env.clock.Advance(31 * time.Second)
	resp, replay := refresh(tok.RefreshToken)
	if resp.StatusCode != http.StatusBadRequest || replay.Error != "invalid_grant" {
		t.Fatalf("replay status = %d error = %q", resp.StatusCode, replay.Error)
	}
	if replay.Description != "refresh token replay detected" {
		t.Errorf("replay description = %q", replay.Description)
	}
	if _, err := env.store.VerifyAccessToken(first.AccessToken, testIssuer+"/mcp"); err == nil {
		t.Error("access token still valid after refresh replay revocation")
	}
	resp, after := refresh(first.RefreshToken)
	if resp.StatusCode != http.StatusBadRequest || after.Error != "invalid_grant" {
		t.Errorf("refresh after revocation status = %d error = %q", resp.StatusCode, after.Error)
	}
}

func TestAuthorizationCodeReplayRevokesGrant(t *testing.T) {
	env := newTestEnv(t)
	clientID, verifier, code := env.obtainCode()
	resp := env.exchange(clientID, verifier, code)
	tok := decodeToken(t, resp)
	if tok.AccessToken == "" {
		t.Fatalf("exchange failed: %+v", tok)
	}

	resp = env.exchange(clientID, verifier, code)
	replay := decodeToken(t, resp)
	if resp.StatusCode != http.StatusBadRequest || replay.Error != "invalid_grant" {
		t.Fatalf("replay status = %d error = %q", resp.StatusCode, replay.Error)
	}
	if _, err := env.store.VerifyAccessToken(tok.AccessToken, testIssuer+"/mcp"); err == nil {
		t.Error("access token still valid after code replay")
	}
}

func TestBadPKCERejected(t *testing.T) {
	env := newTestEnv(t)
	clientID, _, code := env.obtainCode()
	wrongVerifier, _ := pkcePair(t)
	resp := env.exchange(clientID, wrongVerifier, code)
	out := decodeToken(t, resp)
	if resp.StatusCode != http.StatusBadRequest || out.Error != "invalid_grant" {
		t.Fatalf("status = %d error = %q", resp.StatusCode, out.Error)
	}
	// The code is burned even after a failed verifier.
	resp = env.exchange(clientID, "", code)
	out = decodeToken(t, resp)
	if resp.StatusCode != http.StatusBadRequest || out.Error != "invalid_grant" {
		t.Fatalf("empty verifier status = %d error = %q", resp.StatusCode, out.Error)
	}
}

func TestRevokeEndpointInvalidatesTokens(t *testing.T) {
	env := newTestEnv(t)
	clientID, verifier, code := env.obtainCode()
	tok := decodeToken(t, env.exchange(clientID, verifier, code))
	resp, err := env.client.PostForm(env.server.URL+"/oauth/revoke", url.Values{"token": {tok.RefreshToken}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d", resp.StatusCode)
	}
	if _, err := env.store.VerifyAccessToken(tok.AccessToken, testIssuer+"/mcp"); err == nil {
		t.Error("access token still valid after revoke")
	}
	// Unknown tokens also return 200.
	resp, err = env.client.PostForm(env.server.URL+"/oauth/revoke", url.Values{"token": {"wsb_at_unknown"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("unknown token revoke status = %d", resp.StatusCode)
	}
}

func TestLockoutAfterFiveFailures(t *testing.T) {
	env := newTestEnv(t)
	clientID := env.registerClient()
	_, challenge := pkcePair(t)
	id, csrf := env.authorizeForm(clientID, challenge)

	for i := 0; i < 5; i++ {
		resp := env.approve(id, csrf, "wrong-passphrase")
		status := resp.StatusCode
		resp.Body.Close()
		want := http.StatusOK
		if i == 4 {
			want = http.StatusTooManyRequests
		}
		if status != want {
			t.Fatalf("attempt %d status = %d, want %d", i+1, status, want)
		}
	}
	resp := env.approve(id, csrf, testPass)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("correct passphrase while locked status = %d body = %s", resp.StatusCode, raw)
	}
	env.clock.Advance(5*time.Minute + time.Second)
	resp = env.approve(id, csrf, testPass)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("after lockout status = %d body = %s", resp.StatusCode, raw)
	}
}

func TestCSRFAndDeny(t *testing.T) {
	env := newTestEnv(t)
	clientID := env.registerClient()
	_, challenge := pkcePair(t)
	id, csrf := env.authorizeForm(clientID, challenge)

	resp := env.approve(id, "not-the-token", testPass)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bad CSRF status = %d, want 403", resp.StatusCode)
	}

	resp, err := env.client.PostForm(env.server.URL+"/oauth/authorize", url.Values{
		"auth_req_id": {id},
		"csrf_token":  {csrf},
		"action":      {"deny"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("deny status = %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	q := loc.Query()
	if q.Get("error") != "access_denied" || q.Get("iss") != testIssuer || q.Get("state") != "client-state-123" {
		t.Errorf("deny Location = %q", resp.Header.Get("Location"))
	}
	if q.Get("code") != "" {
		t.Error("deny redirect contains a code")
	}
}

func TestAuditLogNeverContainsSecrets(t *testing.T) {
	env := newTestEnv(t)
	clientID, verifier, code := env.obtainCode()
	tok := decodeToken(t, env.exchange(clientID, verifier, code))
	resp, err := env.client.PostForm(env.server.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {clientID},
	})
	if err != nil {
		t.Fatal(err)
	}
	second := decodeToken(t, resp)
	resp, err = env.client.PostForm(env.server.URL+"/oauth/revoke", url.Values{"token": {second.AccessToken}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	raw, err := os.ReadFile(env.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"dcr_register", "authorize_attempt", "token_issue", "token_refresh", "grant_revoke"} {
		if !strings.Contains(string(raw), `"event":"`+event+`"`) {
			t.Errorf("audit log missing event %q:\n%s", event, raw)
		}
	}
	for _, secret := range []string{testPass, verifier, code, tok.AccessToken, tok.RefreshToken, second.AccessToken, second.RefreshToken} {
		if secret != "" && strings.Contains(string(raw), secret) {
			t.Errorf("audit log contains a secret value %q:\n%s", secret, raw)
		}
	}
}

func TestRegisterAllowsLoopbackHTTP(t *testing.T) {
	env := newTestEnv(t)
	for _, uri := range []string{"http://127.0.0.1:8080/cb", "http://localhost:3000/cb", "http://[::1]:9000/cb"} {
		body := fmt.Sprintf(`{"redirect_uris":[%q]}`, uri)
		resp, err := env.client.Post(env.server.URL+"/oauth/register", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("%s: status = %d body = %s", uri, resp.StatusCode, raw)
		}
	}
}

func TestAuthorizationCodeExpires(t *testing.T) {
	env := newTestEnv(t)
	clientID, verifier, code := env.obtainCode()
	env.clock.Advance(61 * time.Second)
	resp := env.exchange(clientID, verifier, code)
	out := decodeToken(t, resp)
	if resp.StatusCode != http.StatusBadRequest || out.Error != "invalid_grant" {
		t.Fatalf("expired code status = %d error = %q", resp.StatusCode, out.Error)
	}
}

func TestRegisterClientLimit(t *testing.T) {
	env := newTestEnv(t)
	for i := 0; i < oauth.MaxClients; i++ {
		err := env.store.RegisterClient(&oauth.ClientRecord{
			ClientID:     fmt.Sprintf("wsb_cli_%06d", i),
			ClientName:   "client",
			RedirectURIs: []string{"https://claude.ai/cb"},
			CreatedAt:    env.clock.Now(),
			Activated:    true,
		})
		if err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
	}
	err := env.store.RegisterClient(&oauth.ClientRecord{
		ClientID:     "wsb_cli_overflow",
		RedirectURIs: []string{"https://claude.ai/cb"},
		CreatedAt:    env.clock.Now(),
		Activated:    true,
	})
	if !errors.Is(err, oauth.ErrClientLimit) {
		t.Fatalf("RegisterClient beyond limit = %v, want ErrClientLimit", err)
	}
}

func TestPeekMeta(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wsbridge.db")
	if _, err := oauth.PeekMeta(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing database error = %v, want os.ErrNotExist", err)
	}
	store, err := oauth.OpenStore(path, oauth.StoreOptions{Issuer: testIssuer})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := oauth.HashAdminPassphrase(testPass, oauth.Argon2Params{
		Memory: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetAdminHash(hash); err != nil {
		t.Fatal(err)
	}
	if _, err := oauth.PeekMeta(path); !errors.Is(err, bolt.ErrTimeout) {
		t.Errorf("PeekMeta while the store is open = %v, want bolt.ErrTimeout", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	meta, err := oauth.PeekMeta(path)
	if err != nil {
		t.Fatalf("PeekMeta: %v", err)
	}
	if meta.Issuer != testIssuer || !meta.AdminPassphraseSet || meta.SchemaVersion != oauth.SchemaVersion {
		t.Errorf("meta = %+v", meta)
	}
}

func TestPKCEHelpers(t *testing.T) {
	// The HTTP flow exercises code expiry and replay; this asserts the
	// exported PKCE shape checks.
	if !oauth.ValidPKCEChallenge("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Error("43-char challenge rejected")
	}
	if oauth.ValidPKCEChallenge("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Error("42-char challenge accepted")
	}
	if oauth.VerifyPKCE("short", "short") {
		t.Error("invalid verifier accepted")
	}
}

func TestAuthorizeCSPAllowsExternalRedirect(t *testing.T) {
	env := newTestEnv(t)
	clientID := env.registerClient()
	_, challenge := pkcePair(t)
	u := env.server.URL + "/oauth/authorize?response_type=code&client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape("https://chatgpt.com/connector_platform_oauth_redirect") +
		"&scope=mcp:tools&code_challenge=" + challenge + "&code_challenge_method=S256"
	resp, err := env.client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if strings.Contains(csp, "form-action 'self'") {
		t.Fatalf("CSP %q restricts form-action to 'self', which blocks 302 OAuth callback redirects in Chromium", csp)
	}
}
