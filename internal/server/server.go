// Package server implements the loopback-only dashboard HTTP server: the
// JSON API and the embedded frontend.
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/enigma-137/ven/internal/app"
	"github.com/enigma-137/ven/internal/vault"
)

const (
	cookieName = "ven_session"
	csrfHeader = "X-CSRF-Token"

	// sessionIdleTimeout ends a browser session (locked or not) after inactivity.
	sessionIdleTimeout = 2 * time.Hour
	// sessionMaxAge is the absolute session lifetime.
	sessionMaxAge = 12 * time.Hour

	maxBodyBytes   = 64 << 10
	maxImportBytes = 4 << 20 // JSON-encoded content; decoded content is capped separately
	maxSessions    = 32
)

// Config configures a Server.
type Config struct {
	App *app.App
	// LaunchToken must be presented to create a browser session. It is
	// printed by `ven ui` inside the URL fragment, which browsers never send.
	LaunchToken string
	// Static holds the built frontend (index.html at its root). May be nil.
	Static fs.FS
	// Logger receives request lines; never values, passwords or bodies.
	Logger *log.Logger
	// Now overrides the clock (tests).
	Now func() time.Time
}

type session struct {
	id           string
	csrf         string
	created      time.Time
	lastSeen     time.Time
	lastActivity time.Time // last authenticated action; drives auto-lock
	key          *vault.Key
}

// Server is the dashboard HTTP server.
type Server struct {
	cfg    Config
	mux    *http.ServeMux
	static http.Handler

	mu       sync.Mutex
	sessions map[string]*session
	hosts    map[string]bool
	origins  map[string]bool

	unlockMu sync.Mutex // serializes password checks
	throttle throttle
}

// New builds a server. Call SetAddr before serving.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(discard{}, "", 0)
	}
	s := &Server{cfg: cfg, sessions: map[string]*session{}, mux: http.NewServeMux()}
	s.static = newStaticHandler(cfg.Static)
	s.routes()
	return s
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// SetAddr records the bound address and derives the allowed Host and
// Origin values. Only loopback names for that exact port are accepted.
func (s *Server) SetAddr(addr string) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hosts = map[string]bool{}
	s.origins = map[string]bool{}
	for _, h := range []string{"127.0.0.1", "localhost", "[::1]"} {
		hp := h + ":" + port
		s.hosts[hp] = true
		s.origins["http://"+hp] = true
	}
}

// Serve runs the server on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.SetAddr(ln.Addr().String())
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          s.cfg.Logger,
	}
	go s.sweepLoop(ctx)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	err := srv.Serve(ln)
	s.LockAll()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// LockAll destroys every in-memory vault key and ends all sessions.
func (s *Server) LockAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		sess.key.Destroy()
		delete(s.sessions, id)
	}
}

func (s *Server) sweepLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweep()
		}
	}
}

// sweep enforces auto-lock and session expiry even without requests, so
// keys do not linger in memory.
func (s *Server) sweep() {
	autoLock := time.Duration(s.cfg.App.AutoLockMinutes(context.Background())) * time.Minute
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		s.expireLocked(id, sess, now, autoLock)
	}
}

// expireLocked applies auto-lock and expiry to one session. It returns
// false if the session was removed. Callers hold s.mu.
func (s *Server) expireLocked(id string, sess *session, now time.Time, autoLock time.Duration) bool {
	if now.Sub(sess.lastSeen) > sessionIdleTimeout || now.Sub(sess.created) > sessionMaxAge {
		sess.key.Destroy()
		delete(s.sessions, id)
		return false
	}
	if sess.key != nil && now.Sub(sess.lastActivity) > autoLock {
		sess.key.Destroy()
		sess.key = nil
	}
	return true
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// NewLaunchToken returns a random token for Config.LaunchToken.
func NewLaunchToken() string { return randomToken() }

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// throttle slows repeated password failures: after 5 consecutive failures
// each further attempt waits 2^(n-5) seconds, capped at 5 minutes.
type throttle struct {
	mu       sync.Mutex
	failures int
	until    time.Time
}

func (t *throttle) wait(now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Before(t.until) {
		return t.until.Sub(now)
	}
	return 0
}

func (t *throttle) fail(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failures++
	if t.failures >= 5 {
		d := time.Second << min(t.failures-5, 9)
		if d > 5*time.Minute {
			d = 5 * time.Minute
		}
		t.until = now.Add(d)
	}
}

func (t *throttle) success() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failures = 0
	t.until = time.Time{}
}

// Handler returns the full middleware chain.
func (s *Server) Handler() http.Handler {
	return s.logRequests(s.securityHeaders(s.checkHost(s.mux)))
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.cfg.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		// Paths contain only slugs and IDs; query strings are omitted.
		s.cfg.Logger.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.status, s.cfg.Now().Sub(start).Round(time.Millisecond))
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

const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
			h.Set("Pragma", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

// checkHost rejects requests whose Host is not our loopback address,
// defeating DNS rebinding.
func (s *Server) checkHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		ok := s.hosts[strings.ToLower(r.Host)]
		s.mu.Unlock()
		if !ok {
			writeError(w, http.StatusMisdirectedRequest, "invalid_host", "invalid Host header")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isStateChanging(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// checkOrigin enforces same-origin access to the API. Cross-site fetch
// metadata is refused for every API request; state-changing requests must
// also carry an allowed Origin header.
func (s *Server) checkOrigin(w http.ResponseWriter, r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		writeError(w, http.StatusForbidden, "forbidden_origin", "cross-site requests are not allowed")
		return false
	}
	if !isStateChanging(r.Method) {
		return true
	}
	origin := r.Header.Get("Origin")
	s.mu.Lock()
	ok := s.origins[origin]
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden_origin", "missing or disallowed Origin header")
		return false
	}
	return true
}

func (s *Server) sessionFromRequest(r *http.Request) (*session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil || len(c.Value) != 64 {
		return nil, false
	}
	now := s.cfg.Now()
	autoLock := time.Duration(s.cfg.App.AutoLockMinutes(r.Context())) * time.Minute
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if constantTimeEqual(id, c.Value) {
			if !s.expireLocked(id, sess, now, autoLock) {
				return nil, false
			}
			return sess, true
		}
	}
	return nil, false
}

func (s *Server) newSession(w http.ResponseWriter) *session {
	now := s.cfg.Now()
	sess := &session{id: randomToken(), csrf: randomToken(), created: now, lastSeen: now, lastActivity: now}
	s.mu.Lock()
	if len(s.sessions) >= maxSessions {
		// Evict the least recently seen session.
		var oldest *session
		for _, o := range s.sessions {
			if oldest == nil || o.lastSeen.Before(oldest.lastSeen) {
				oldest = o
			}
		}
		oldest.key.Destroy()
		delete(s.sessions, oldest.id)
	}
	s.sessions[sess.id] = sess
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    sess.id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// Secure is omitted: the dashboard is plain HTTP on loopback.
	})
	return sess
}

func (s *Server) endSession(w http.ResponseWriter, sess *session) {
	s.mu.Lock()
	sess.key.Destroy()
	sess.key = nil
	delete(s.sessions, sess.id)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// reqCtx is passed to API handlers.
type reqCtx struct {
	sess *session
	key  *vault.Key
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, rc *reqCtx)

type access int

const (
	accessPublic   access = iota // no session needed (session bootstrap/status)
	accessSession                // session + CSRF
	accessUnlocked               // session + CSRF + unlocked vault
)

// api wraps a handler with origin, session, CSRF and lock checks. Lock state
// is re-checked on every request, never trusted from the client.
func (s *Server) api(level access, limit int64, h handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.checkOrigin(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		rc := &reqCtx{}
		if level == accessPublic {
			rc.sess, _ = s.sessionFromRequest(r)
			h(w, r, rc)
			return
		}
		sess, ok := s.sessionFromRequest(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "no_session", "no active dashboard session; open the link printed by `ven ui`")
			return
		}
		if !constantTimeEqual(r.Header.Get(csrfHeader), sess.csrf) {
			writeError(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token")
			return
		}
		now := s.cfg.Now()
		s.mu.Lock()
		sess.lastSeen = now
		key := sess.key
		if key != nil {
			sess.lastActivity = now
		}
		s.mu.Unlock()
		rc.sess = sess
		if level == accessUnlocked {
			if key == nil {
				writeError(w, http.StatusUnauthorized, "locked", "the vault is locked")
				return
			}
			rc.key = key
		}
		h(w, r, rc)
	}
}

func (s *Server) setKey(sess *session, k *vault.Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess.key.Destroy()
	sess.key = k
	sess.lastActivity = s.cfg.Now()
}

func (s *Server) lockSession(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess.key.Destroy()
	sess.key = nil
}

func (s *Server) isUnlocked(sess *session) bool {
	if sess == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return sess.key != nil
}
