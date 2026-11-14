package mcpsrv_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wsbridge/internal/mcpsrv"
	"wsbridge/internal/oauth"
	"wsbridge/internal/ws"
)

const testResource = "https://bridge.example.com/mcp"

type fakeVerifier struct {
	principals map[string]*oauth.GrantPrincipal
}

func (f fakeVerifier) VerifyAccessToken(raw, resource string) (*oauth.GrantPrincipal, error) {
	p, ok := f.principals[raw]
	if !ok || resource != testResource {
		return nil, oauth.ErrInvalidToken
	}
	return p, nil
}

func newAuthServer(t *testing.T, principals map[string]*oauth.GrantPrincipal) http.Handler {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr, err := ws.NewManager([]ws.WorkspaceConfig{{
		Name: "app", Path: dir, MaxPerm: ws.PermRead,
	}}, ws.ManagerOptions{DataDir: t.TempDir(), RipgrepPath: "none"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	srv, err := mcpsrv.New(mcpsrv.Options{
		Manager: mgr,
		Version: "test",
		Scope:   mcpsrv.GrantScope(mgr),
		Auth: &mcpsrv.AuthConfig{
			Verifier:            fakeVerifier{principals: principals},
			ResourceURL:         testResource,
			ResourceMetadataURL: "https://bridge.example.com/.well-known/oauth-protected-resource/mcp",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler()
}

func principal(grantID string) *oauth.GrantPrincipal {
	return &oauth.GrantPrincipal{
		GrantID:  grantID,
		ClientID: "wsb_cli_test",
		Scopes:   []string{"mcp:tools", "offline_access"},
		Workspaces: map[string]ws.Permission{
			"app": ws.PermRead,
		},
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func TestBearerRequiredReturnsSpec401(t *testing.T) {
	handler := newAuthServer(t, map[string]*oauth.GrantPrincipal{"good": principal("wsb_grt_a")})
	server := httptest.NewServer(handler)
	defer server.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}`
	for _, path := range []string{"/mcp", "/mcp/"} {
		t.Run(path, func(t *testing.T) {
			for _, header := range []string{"", "Bearer wrong"} {
				req, err := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept", "application/json, text/event-stream")
				if header != "" {
					req.Header.Set("Authorization", header)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401: %s", resp.StatusCode, raw)
				}
				if loc := resp.Header.Get("Location"); loc != "" {
					t.Errorf("redirect Location = %q", loc)
				}
				if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
					t.Errorf("Content-Type = %q", ct)
				}
				if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
					t.Errorf("Cache-Control = %q", cc)
				}
				want := `{"error":"invalid_token","error_description":"missing or invalid bearer token"}`
				if string(raw) != want {
					t.Errorf("body = %q, want %q", raw, want)
				}
				www := resp.Header.Get("WWW-Authenticate")
				if !strings.Contains(www, `resource_metadata="https://bridge.example.com/.well-known/oauth-protected-resource/mcp"`) {
					t.Errorf("WWW-Authenticate = %q", www)
				}
			}
		})
	}
}

func initialize(t *testing.T, client *http.Client, base, token string) string {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}`
	req, err := http.NewRequest(http.MethodPost, base+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize status = %d", resp.StatusCode)
	}
	session := resp.Header.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatal("initialize response has no Mcp-Session-Id")
	}
	return session
}

func TestSessionIsBoundToGrant(t *testing.T) {
	handler := newAuthServer(t, map[string]*oauth.GrantPrincipal{
		"alpha": principal("wsb_grt_a"),
		"beta":  principal("wsb_grt_b"),
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	client := server.Client()

	session := initialize(t, client, server.URL, "alpha")

	call := func(token string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, server.URL+"/mcp",
			bytes.NewBufferString(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Mcp-Session-Id", session)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}
	if resp := call("alpha"); resp.StatusCode >= 400 {
		t.Fatalf("same-grant notification status = %d", resp.StatusCode)
	}
	if resp := call("beta"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-grant session status = %d, want 403", resp.StatusCode)
	}
}

func TestToolsListWithBearer(t *testing.T) {
	handler := newAuthServer(t, map[string]*oauth.GrantPrincipal{"good": principal("wsb_grt_a")})
	server := httptest.NewServer(handler)
	defer server.Close()
	client := server.Client()
	session := initialize(t, client, server.URL, "good")

	req, err := http.NewRequest(http.MethodPost, server.URL+"/mcp",
		bytes.NewBufferString(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", session)
	req.Header.Set("Authorization", "Bearer good")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	req, err = http.NewRequest(http.MethodPost, server.URL+"/mcp",
		bytes.NewBufferString(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", session)
	req.Header.Set("Authorization", "Bearer good")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list status = %d: %s", resp.StatusCode, raw)
	}
	if !bytes.Contains(raw, []byte("read_file")) {
		t.Fatalf("tools/list response missing tools: %s", raw)
	}
	var envelope struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		// SSE-framed responses are valid too; the substring check above is
		// the portable assertion.
		t.Logf("non-JSON tools/list body: %v", err)
	} else if len(envelope.Result.Tools) != 7 {
		t.Errorf("tools = %d, want 7", len(envelope.Result.Tools))
	}
}
