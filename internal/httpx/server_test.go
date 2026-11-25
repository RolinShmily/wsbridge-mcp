package httpx_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RolinShmily/wsbridge-mcp/internal/httpx"
)

func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s never became ready", addr)
}

func startServer(t *testing.T, srv *httpx.Server) (cancel context.CancelFunc, errCh <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	go func() { ch <- srv.Start(ctx) }()
	return cancel, ch
}

func stopServer(t *testing.T, cancel context.CancelFunc, errCh <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned error after cancel: %v", err)
		}
	case <-time.After(8 * time.Second):
		// net/http.Shutdown treats a StateNew connection as idle only after
		// five seconds (Go issue 22682), so the graceful-shutdown window must
		// be longer than that to avoid racing the test deadline.
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("Start did not return after context cancellation:\n%s", buf[:n])
	}
}

func TestServerStartServesAndShutsDownGracefully(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv := httpx.New(httpx.Options{
		Listener: ln,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "ok")
		}),
		Logger: newTestLogger(&bytes.Buffer{}),
	})
	cancel, errCh := startServer(t, srv)
	waitForTCP(t, ln.Addr().String())

	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		cancel()
		t.Fatalf("GET server: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("response = %d %q", resp.StatusCode, body)
	}
	if got := srv.Addr(); got == nil || got.String() != ln.Addr().String() {
		t.Errorf("Addr = %v, want %v", got, ln.Addr())
	}
	stopServer(t, cancel, errCh)
}

func TestServerForcesShutdownOfLongLivedStreams(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	entered := make(chan struct{}, 1)
	srv := httpx.New(httpx.Options{
		Listener: ln,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			entered <- struct{}{}
			<-r.Context().Done()
		}),
		Logger:          newTestLogger(&bytes.Buffer{}),
		ShutdownTimeout: 100 * time.Millisecond,
	})
	cancel, errCh := startServer(t, srv)
	waitForTCP(t, ln.Addr().String())

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://"+ln.Addr().String()+"/stream", nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	clientDone := make(chan error, 1)
	go func() {
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			clientDone <- err
			return
		}
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		clientDone <- err
	}()

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("streaming handler was never entered")
	}

	start := time.Now()
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned error after force-closing streams: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after the force-close deadline")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("shutdown took %v, want about the 100ms timeout", elapsed)
	}

	select {
	case <-clientDone:
	case <-time.After(3 * time.Second):
		t.Error("streaming client was not released by force-close")
	}
}

func TestServerEnforcesDefaultBodyLimit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv := httpx.New(httpx.Options{
		Listener: ln,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.ReadAll(r.Body); err != nil {
				if _, ok := err.(*http.MaxBytesError); ok {
					http.Error(w, "too large", http.StatusRequestEntityTooLarge)
					return
				}
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
		}),
		Logger: newTestLogger(&bytes.Buffer{}),
	})
	cancel, errCh := startServer(t, srv)
	waitForTCP(t, ln.Addr().String())

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Post(
		"http://"+ln.Addr().String()+"/",
		"application/octet-stream",
		strings.NewReader(strings.Repeat("a", 1<<20+1)),
	)
	if err != nil {
		cancel()
		t.Fatalf("POST server: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
	stopServer(t, cancel, errCh)
}

func TestServerAutoListenOnZeroAddr(t *testing.T) {
	srv := httpx.New(httpx.Options{
		Addr:    "127.0.0.1:0",
		Handler: http.NotFoundHandler(),
		Logger:  newTestLogger(&bytes.Buffer{}),
	})
	cancel, errCh := startServer(t, srv)

	deadline := time.Now().Add(3 * time.Second)
	for srv.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.Addr() == nil {
		cancel()
		t.Fatal("Addr is nil after Start")
	}
	addr := srv.Addr().String()
	if strings.HasSuffix(addr, ":0") {
		t.Fatalf("Addr was not resolved: %s", addr)
	}
	waitForTCP(t, addr)

	resp, err := (&http.Client{Timeout: time.Second}).Get("http://" + addr + "/")
	if err != nil {
		cancel()
		t.Fatalf("GET server: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	stopServer(t, cancel, errCh)
}

func TestServerWiresDevCORSAndDebugOAuth(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var logs bytes.Buffer
	var handled atomic.Bool
	srv := httpx.New(httpx.Options{
		Listener: ln,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handled.Store(true)
			w.WriteHeader(http.StatusOK)
		}),
		Logger:     newTestLogger(&logs),
		DevCORS:    true,
		DebugOAuth: true,
	})
	cancel, errCh := startServer(t, srv)
	base := "http://" + ln.Addr().String()
	waitForTCP(t, ln.Addr().String())
	client := &http.Client{Timeout: 2 * time.Second}

	preflight, err := http.NewRequest(http.MethodOptions, base+"/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	preflight.Header.Set("Origin", "http://localhost:6274")
	preflight.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := client.Do(preflight)
	if err != nil {
		cancel()
		t.Fatalf("preflight: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:6274" {
		t.Errorf("preflight ACAO = %q", got)
	}
	if handled.Load() {
		t.Error("preflight reached the MCP handler")
	}

	odd, err := http.NewRequest(http.MethodGet, base+"//mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = client.Do(odd)
	if err != nil {
		cancel()
		t.Fatalf("non-canonical path: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("non-canonical path status = %d, want 400", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("non-canonical path redirected to %q", loc)
	}

	authed, err := http.NewRequest(http.MethodGet, base+"/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	authed.Header.Set("Authorization", "Bearer SUPERSECRETTOKEN")
	authed.Header.Set("Origin", "http://localhost:6274")
	resp, err = client.Do(authed)
	if err != nil {
		cancel()
		t.Fatalf("authorized request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("authorized status = %d, want 200", resp.StatusCode)
	}
	if !handled.Load() {
		t.Error("authorized request did not reach the MCP handler")
	}

	stopServer(t, cancel, errCh)

	logsText := logs.String()
	for _, want := range []string{"oauth_debug", "http_request", "[REDACTED]"} {
		if !strings.Contains(logsText, want) {
			t.Errorf("logs missing %q: %s", want, logsText)
		}
	}
	if strings.Contains(logsText, "SUPERSECRETTOKEN") {
		t.Errorf("logs leaked bearer token: %s", logsText)
	}
}
