// Package server implements `ven server`, the hosted VEN API for accounts,
// teams and sharing. It stores ciphertext, memberships and an audit log in
// SQLite and never sees plaintext values (see internal/e2e).
//
// It is meant to listen on loopback behind a TLS-terminating reverse proxy
// such as Caddy.
package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/enigma-137/ven/internal/remote/api"
	"github.com/enigma-137/ven/internal/storage"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Lifetimes and limits.
const (
	AccessTokenTTL     = time.Hour
	RefreshTokenTTL    = 30 * 24 * time.Hour
	DefaultInviteTTL   = 24 * time.Hour
	MaxInviteTTL       = 7 * 24 * time.Hour
	DefaultMemberTTL   = 30 * 24 * time.Hour
	MaxMemberTTL       = 366 * 24 * time.Hour
	MaxTokenTTL        = 366 * 24 * time.Hour
	maxBodyBytes       = 64 << 10
	maxContentBodySize = 4 << 20 // encrypted dotenv content (1 MiB plaintext) plus JSON/base64 overhead
	sweepInterval      = time.Minute
)

// Config configures a Server.
type Config struct {
	// DBPath is the SQLite database file.
	DBPath string
	// GitHubClientID is the OAuth app client ID used for the device flow.
	GitHubClientID string
	// GitHubURL and GitHubAPIURL default to github.com; tests override them.
	GitHubURL    string
	GitHubAPIURL string
	// TrustProxy uses X-Forwarded-For from loopback peers for client IPs.
	TrustProxy bool
	// HTTPClient is used for identity provider calls.
	HTTPClient *http.Client
	// Logger receives one line per request (never bodies). Nil disables it.
	Logger *log.Logger
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Server is the hosted API.
type Server struct {
	cfg       Config
	db        *storage.DB
	providers map[string]provider
	limiter   *rateLimiter
	mux       *http.ServeMux
}

// New opens the database and builds the server.
func New(cfg Config) (*Server, error) {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	sub, err := fs.Sub(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	db, err := storage.OpenWithMigrations(cfg.DBPath, sub)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, db: db, providers: map[string]provider{}, limiter: newRateLimiter(), mux: http.NewServeMux()}
	if cfg.GitHubClientID != "" {
		s.providers["github"] = newGitHub(cfg)
	}
	if len(s.providers) == 0 {
		db.Close()
		return nil, errors.New("no identity provider configured: set a GitHub OAuth client ID")
	}
	s.routes()
	return s, nil
}

// Close closes the database.
func (s *Server) Close() error { return s.db.Close() }

func (s *Server) now() time.Time { return s.cfg.Now().UTC().Truncate(time.Millisecond) }

// Handler returns the HTTP handler with middleware applied.
func (s *Server) Handler() http.Handler {
	return s.logRequests(s.securityHeaders(s.mux))
}

// Serve runs the HTTP server on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go s.sweepLoop(ctx)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) sweepLoop(ctx context.Context) {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Sweep(ctx); err != nil && s.cfg.Logger != nil {
				s.cfg.Logger.Printf("sweep: %v", err)
			}
			s.limiter.cleanup(s.now())
		}
	}
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	if s.cfg.Logger == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		// Paths contain project and environment slugs, never secrets.
		s.cfg.Logger.Printf("%s %s %s %d %s", s.clientIP(r), r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the peer address, or the proxy-reported client when the
// peer is a trusted loopback proxy.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if s.cfg.TrustProxy {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				// The proxy appends the address it saw; earlier entries are client-controlled.
				if last := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(last) != nil {
					return last
				}
			}
		}
	}
	return host
}

// httpError is returned by handlers and rendered as api.Error.
type httpError struct {
	status int
	code   string
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func errorf(status int, code, format string, args ...any) error {
	return &httpError{status: status, code: code, msg: fmt.Sprintf(format, args...)}
}

var (
	errNotFound  = errorf(http.StatusNotFound, api.CodeNotFound, "not found")
	errForbidden = errorf(http.StatusForbidden, api.CodeForbidden, "you do not have permission to do that")
)

func invalid(format string, args ...any) error {
	return errorf(http.StatusBadRequest, api.CodeInvalid, format, args...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeErr(w http.ResponseWriter, err error) {
	var he *httpError
	switch {
	case errors.As(err, &he):
		writeJSON(w, he.status, api.Error{Code: he.code, Message: he.msg})
	case errors.Is(err, storage.ErrNotFound):
		writeJSON(w, http.StatusNotFound, api.Error{Code: api.CodeNotFound, Message: "not found"})
	case errors.Is(err, storage.ErrConflict):
		writeJSON(w, http.StatusConflict, api.Error{Code: api.CodeConflict, Message: "already exists"})
	default:
		if s.cfg.Logger != nil {
			s.cfg.Logger.Printf("internal error: %v", err)
		}
		writeJSON(w, http.StatusInternalServerError, api.Error{Code: api.CodeInternal, Message: "internal server error"})
	}
}

func decode(r *http.Request, limit int64, v any) error {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return errorf(http.StatusUnsupportedMediaType, api.CodeInvalid, "Content-Type must be application/json")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, limit+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("malformed JSON body")
	}
	if dec.More() {
		return invalid("unexpected data after JSON body")
	}
	return nil
}

// rateLimiter is a per-key token bucket for unauthenticated endpoints.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter() *rateLimiter { return &rateLimiter{buckets: map[string]*bucket{}} }

// allow takes one token from key's bucket (burst capacity, refill per minute).
func (l *rateLimiter) allow(key string, burst, perMinute float64, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(burst, b.tokens+now.Sub(b.last).Minutes()*perMinute)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *rateLimiter) cleanup(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if now.Sub(b.last) > time.Hour {
			delete(l.buckets, k)
		}
	}
}

func (s *Server) limit(r *http.Request, name string, burst, perMinute float64) error {
	if !s.limiter.allow(name+"|"+s.clientIP(r), burst, perMinute, s.now()) {
		return errorf(http.StatusTooManyRequests, api.CodeRateLimited, "too many requests; try again in a minute")
	}
	return nil
}
