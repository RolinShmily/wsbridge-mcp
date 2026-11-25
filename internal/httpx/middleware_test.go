package httpx_test

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RolinShmily/wsbridge-mcp/internal/httpx"
)

func TestBodyLimit(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			if _, ok := err.(*http.MaxBytesError); ok {
				http.Error(w, "too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	h := httpx.BodyLimit(1024)(handler)

	t.Run("small body accepted", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("hello"))
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("oversized body rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("a", 2048)))
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want 413", rec.Code)
		}
	})
}

func TestRejectNonCanonicalPaths(t *testing.T) {
	allowed := []string{"/", "/mcp", "/mcp/", "/a/b", "/a/b/"}
	rejected := []string{"//mcp", "/./mcp", "/a/../mcp", "/a//b", "/mcp//", "//"}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := httpx.RejectNonCanonicalPaths()(handler)

	for _, p := range allowed {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.com"+p, nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("path %q status = %d, want 200", p, rec.Code)
		}
	}
	for _, p := range rejected {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://example.com"+p, nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("path %q status = %d, want 400", p, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("path %q returned Location %q", p, loc)
		}
	}
}

func TestRejectNonCanonicalPathsBeforeRealMux(t *testing.T) {
	mux := http.NewServeMux()
	h := httpx.RejectNonCanonicalPaths()(mux)

	tests := []struct {
		name   string
		target string
		want   int
	}{
		{"empty absolute-form path", "http://example.com", http.StatusBadRequest},
		{"double slash", "http://example.com//mcp", http.StatusBadRequest},
		{"dot segment", "http://example.com/./mcp", http.StatusBadRequest},
		{"canonical path reaches mux", "http://example.com/mcp", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Errorf("redirected to %q", loc)
			}
		})
	}
}

func TestDevCORSAllowlistedOrigin(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	h := httpx.DevCORS(true)(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Origin", "http://localhost:6274")
	h.ServeHTTP(rec, req)

	if !called {
		t.Fatal("handler was not called")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:6274" {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Origin") {
		t.Errorf("Vary = %q, want Origin", got)
	}
}

func TestDevCORSRejectsForeignOrigin(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := httpx.DevCORS(true)(handler)

	for _, origin := range []string{"https://evil.example.com", "http://localhost.evil.com", "http://127.0.0.2:1234"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Origin", origin)
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("origin %q: Access-Control-Allow-Origin = %q, want empty", origin, got)
		}
	}
}

func TestDevCORSPreflight(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	h := httpx.DevCORS(true)(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/mcp", nil)
	req.Header.Set("Origin", "http://127.0.0.1:6274")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
	h.ServeHTTP(rec, req)

	if called {
		t.Fatal("preflight reached the MCP handler")
	}
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:6274" {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(strings.ToLower(got), "authorization") {
		t.Errorf("Access-Control-Allow-Headers = %q", got)
	}
}

func TestDevCORSDisabled(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := httpx.DevCORS(false)(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Origin", "http://localhost:6274")
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty", got)
	}
}

func newTestLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestAccessLogRedactsQuerySecrets(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := httpx.AccessLog(logger)(handler)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token?code=AUTHCODE&state=STATE", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	logs := buf.String()
	if strings.Contains(logs, "AUTHCODE") {
		t.Errorf("access log leaked authorization code: %s", logs)
	}
	if !strings.Contains(logs, "[REDACTED]") {
		t.Errorf("access log is missing redaction marker: %s", logs)
	}
	if !strings.Contains(logs, "state=STATE") {
		t.Errorf("access log unexpectedly hid state: %s", logs)
	}
	if !strings.Contains(logs, "status=200") {
		t.Errorf("access log missing status: %s", logs)
	}
}

func TestDebugOAuthLogsRedactedHeaders(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	h := httpx.DebugOAuth(logger, true)(handler)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.Header.Set("Authorization", "Bearer SUPERSECRETTOKEN")
	req.Header.Set("Cookie", "session=SUPERSECRETCOOKIE")
	req.Header.Set("X-Debug", "visible")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	logs := buf.String()
	if !strings.Contains(logs, "oauth_debug") {
		t.Fatalf("debug log missing: %s", logs)
	}
	for _, secret := range []string{"SUPERSECRETTOKEN", "SUPERSECRETCOOKIE"} {
		if strings.Contains(logs, secret) {
			t.Errorf("debug log leaked %q: %s", secret, logs)
		}
	}
	if !strings.Contains(logs, "[REDACTED]") {
		t.Errorf("debug log missing redaction marker: %s", logs)
	}
	if !strings.Contains(logs, "visible") {
		t.Errorf("debug log dropped non-sensitive header: %s", logs)
	}
	if !strings.Contains(logs, "status=502") {
		t.Errorf("debug log missing status: %s", logs)
	}
}

func TestDebugOAuthDisabled(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	h := httpx.DebugOAuth(logger, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if buf.Len() != 0 {
		t.Errorf("disabled debug logger wrote %q", buf.String())
	}
}
