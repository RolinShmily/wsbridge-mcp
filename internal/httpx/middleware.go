package httpx

import (
	"bufio"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"time"
)

// Middleware wraps an http.Handler with cross-cutting behavior.
type Middleware func(http.Handler) http.Handler

// Chain applies middlewares so that mws[0] is the outermost wrapper.
func Chain(handler http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		handler = mws[i](handler)
	}
	return handler
}

// RejectNonCanonicalPaths returns 400 for request paths that http.ServeMux
// would otherwise canonicalize with a 307 redirect. wsbridge must never
// redirect outside /oauth/authorize because cloud MCP runtimes drop the
// Authorization header on redirects.
func RejectNonCanonicalPaths() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			if p == "" {
				// ServeMux would canonicalize an empty path to "/" with a 3xx.
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "non-canonical request path", http.StatusBadRequest)
				return
			}
			cleaned := path.Clean(p)
			if p != cleaned && !(cleaned != "/" && p == cleaned+"/") {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "non-canonical request path", http.StatusBadRequest)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// BodyLimit caps the number of bytes read from a request body. Handlers that
// read past the limit receive an *http.MaxBytesError and should reply 413.
func BodyLimit(maxBytes int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AccessLog records one sanitized line per request. It never logs headers or
// bodies; query parameters are passed through RedactURL.
func AccessLog(logger *slog.Logger) Middleware {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &responseRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			logger.Info("http_request",
				"method", r.Method,
				"path", RedactURL(r.URL.RequestURI()),
				"status", rec.statusCode(),
				"bytes", rec.bytes,
				"duration_ms", time.Since(start).Milliseconds(),
				"remote", r.RemoteAddr,
			)
		})
	}
}

// DebugOAuth emits sanitized OAuth handshake details (method, URL, headers,
// and status) at debug level. It is a no-op unless enabled.
func DebugOAuth(logger *slog.Logger, enabled bool) Middleware {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		if !enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			headers := RedactHeaders(r.Header)
			rec := &responseRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			logger.Debug("oauth_debug",
				"method", r.Method,
				"url", RedactURL(r.URL.RequestURI()),
				"headers", headers,
				"status", rec.statusCode(),
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

// DevCORS permits browser clients served from http://localhost:* and
// http://127.0.0.1:* to call the local server. Disabled by default.
func DevCORS(enabled bool) Middleware {
	return func(next http.Handler) http.Handler {
		if !enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Vary", "Origin")
			origin := r.Header.Get("Origin")
			allowed := origin != "" && isAllowedDevOrigin(origin)
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id, MCP-Protocol-Version")
			}

			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				w.Header().Add("Vary", "Access-Control-Request-Method")
				w.Header().Add("Vary", "Access-Control-Request-Headers")
				if allowed {
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID")
					w.Header().Set("Access-Control-Max-Age", "600")
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isAllowedDevOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1":
		return true
	default:
		return false
	}
}

// responseRecorder records the response status and byte count while
// preserving streaming capabilities of the wrapped ResponseWriter.
type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *responseRecorder) statusCode() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}

func (r *responseRecorder) WriteHeader(code int) {
	if r.status != 0 {
		return
	}
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	r.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *responseRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *responseRecorder) Flush() {
	_ = http.NewResponseController(r.ResponseWriter).Flush()
}

func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(r.ResponseWriter).Hijack()
}
