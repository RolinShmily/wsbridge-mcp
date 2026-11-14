// Package httpx provides the HTTP server, middleware chain, and log
// redaction helpers used by wsbridge.
package httpx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	// DefaultAddr keeps the service on the loopback interface.
	DefaultAddr = "127.0.0.1:8787"
	// DefaultMaxBodyBytes is the hard request-body limit (1 MiB).
	DefaultMaxBodyBytes int64 = 1 << 20
	// DefaultReadHeaderTimeout bounds slowloris header attacks.
	DefaultReadHeaderTimeout = 10 * time.Second
	// DefaultReadTimeout bounds request-body reads. It does not affect
	// response streaming, which is what MCP Streamable HTTP uses.
	DefaultReadTimeout = 30 * time.Second
	// DefaultIdleTimeout closes idle keep-alive connections.
	DefaultIdleTimeout = 120 * time.Second
	// DefaultShutdownTimeout bounds graceful shutdown.
	DefaultShutdownTimeout = 10 * time.Second
)

// Options configures a Server. Zero values select secure defaults.
type Options struct {
	Addr    string
	Handler http.Handler
	Logger  *slog.Logger
	// Listener, when non-nil, is used instead of opening Addr. Tests use this
	// to bind an ephemeral port and learn it without polling.
	Listener net.Listener

	DebugOAuth bool
	DevCORS    bool

	MaxBodyBytes      int64
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

// Server is an http.Server with wsbridge middleware and graceful shutdown.
type Server struct {
	opts    Options
	handler http.Handler
	logger  *slog.Logger

	mu   sync.Mutex
	addr net.Addr
}

// New builds a Server, applies defaults, and wraps the handler with the
// standard middleware chain.
func New(opts Options) *Server {
	if opts.Handler == nil {
		opts.Handler = http.NotFoundHandler()
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if opts.ReadHeaderTimeout <= 0 {
		opts.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = DefaultReadTimeout
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = DefaultIdleTimeout
	}
	if opts.ShutdownTimeout <= 0 {
		opts.ShutdownTimeout = DefaultShutdownTimeout
	}

	handler := Chain(opts.Handler,
		AccessLog(opts.Logger),
		RejectNonCanonicalPaths(),
		DebugOAuth(opts.Logger, opts.DebugOAuth),
		DevCORS(opts.DevCORS),
		BodyLimit(opts.MaxBodyBytes),
	)

	s := &Server{
		opts:    opts,
		handler: handler,
		logger:  opts.Logger,
	}
	if opts.Listener != nil {
		s.addr = opts.Listener.Addr()
	}
	return s
}

// Addr returns the bound address, or nil before the listener is created.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// Start listens (unless a Listener was supplied) and serves until ctx is
// canceled, then shuts down gracefully. A clean shutdown returns nil.
func (s *Server) Start(ctx context.Context) error {
	ln := s.opts.Listener
	if ln == nil {
		addr := s.opts.Addr
		if addr == "" {
			addr = DefaultAddr
		}
		var err error
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("httpx: listen on %q: %w", addr, err)
		}
	}
	s.mu.Lock()
	s.addr = ln.Addr()
	s.mu.Unlock()

	httpServer := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: s.opts.ReadHeaderTimeout,
		ReadTimeout:       s.opts.ReadTimeout,
		WriteTimeout:      s.opts.WriteTimeout,
		IdleTimeout:       s.opts.IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpServer.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.opts.ShutdownTimeout)
		defer cancel()
		shutdownErr := httpServer.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			_ = httpServer.Close()
		}
		serveErr := <-errCh
		switch {
		case shutdownErr == nil:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				return fmt.Errorf("httpx: serve: %w", serveErr)
			}
			return nil
		case errors.Is(shutdownErr, context.DeadlineExceeded):
			// Long-lived MCP Streamable HTTP responses (standalone SSE GETs)
			// do not finish on their own. After the graceful window, Closing
			// them is an intentional, successful shutdown rather than an error.
			s.logger.Warn("shutdown timed out; closed remaining connections",
				"timeout", s.opts.ShutdownTimeout)
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				return fmt.Errorf("httpx: serve: %w", serveErr)
			}
			return nil
		default:
			return fmt.Errorf("httpx: graceful shutdown: %w", shutdownErr)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("httpx: serve: %w", err)
		}
		return nil
	}
}
