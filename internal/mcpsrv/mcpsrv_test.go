package mcpsrv_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"wsbridge/internal/mcpsrv"
	"wsbridge/internal/ws"
)

func newServer(t *testing.T) (*ws.Manager, *mcpsrv.Server, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr, err := ws.NewManager([]ws.WorkspaceConfig{{
		Name: "app", Path: dir, MaxPerm: ws.PermRead,
	}}, ws.ManagerOptions{DataDir: t.TempDir(), RipgrepPath: "none"})
	if err != nil {
		t.Fatalf("ws.NewManager: %v", err)
	}
	srv, err := mcpsrv.New(mcpsrv.Options{Manager: mgr, GrantID: "dev-test", Version: "test"})
	if err != nil {
		_ = mgr.Close()
		t.Fatalf("mcpsrv.New: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	return mgr, srv, dir
}

func TestInitializeOnBothPathsWithoutRedirect(t *testing.T) {
	_, srv, _ := newServer(t)
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}`)
	for _, path := range []string{"/mcp", "/mcp/"} {
		t.Run(path, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, httpServer.URL+path, bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			// A non-localhost Host header must not be rejected: the MCP handler
			// disables the SDK's localhost DNS-rebinding check because OAuth is
			// the authentication boundary.
			req.Host = "wsbridge.example"
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("POST %s: %v", path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound ||
				resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect {
				t.Fatalf("POST %s redirected to %q", path, resp.Header.Get("Location"))
			}
			if resp.StatusCode != http.StatusOK {
				data, _ := io.ReadAll(resp.Body)
				t.Fatalf("POST %s status = %d: %s", path, resp.StatusCode, data)
			}
			data, _ := io.ReadAll(resp.Body)
			if !bytes.Contains(data, []byte(`"serverInfo"`)) {
				t.Fatalf("initialize response missing serverInfo: %s", data)
			}
		})
	}
}

func TestStreamableClientListsAndCallsTools(t *testing.T) {
	_, srv, _ := newServer(t)
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()

	ctx := context.Background()
	for _, path := range []string{"/mcp", "/mcp/"} {
		t.Run(path, func(t *testing.T) {
			client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
			cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
				Endpoint: httpServer.URL + path,
			}, nil)
			if err != nil {
				t.Fatalf("Connect(%s): %v", path, err)
			}
			defer cs.Close()

			list, err := cs.ListTools(ctx, nil)
			if err != nil {
				t.Fatalf("ListTools: %v", err)
			}
			if len(list.Tools) != 7 {
				t.Errorf("got %d tools, want 7", len(list.Tools))
			}
			res, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "read_file",
				Arguments: map[string]any{"path": "a.txt"},
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if res.IsError {
				t.Fatalf("read_file error: %+v", res.Content)
			}
			text, ok := res.Content[0].(*mcp.TextContent)
			if !ok || !strings.Contains(text.Text, "hello") {
				t.Fatalf("read_file content = %+v", res.Content)
			}
		})
	}
}

func TestMountRegistersBothPaths(t *testing.T) {
	_, srv, _ := newServer(t)
	mux := http.NewServeMux()
	srv.Mount(mux)

	for _, path := range []string{"/mcp", "/mcp/"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusMovedPermanently || rec.Code == http.StatusTemporaryRedirect {
			t.Errorf("%s returned a redirect", path)
		}
	}
}

func TestNewRequiresScope(t *testing.T) {
	if _, err := mcpsrv.New(mcpsrv.Options{}); err == nil {
		t.Fatal("New succeeded without a manager or scope")
	}
}
