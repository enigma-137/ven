package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enigma-137/ven/internal/app"
	"github.com/enigma-137/ven/internal/vault"
)

const (
	testHost   = "127.0.0.1:7420"
	testOrigin = "http://127.0.0.1:7420"
	launch     = "test-launch-token"
	masterPW   = "dummy master password"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type client struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
	csrf   string
}

func newTestServer(t *testing.T) (*client, *app.App, *clock) {
	t.Helper()
	a, err := app.Open(filepath.Join(t.TempDir(), "vault.db"), vault.WithKDFParams(vault.KDFParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	clk := &clock{t: time.Now()}
	s := New(Config{App: a, LaunchToken: launch, Now: clk.Now})
	s.SetAddr(testHost)
	return &client{t: t, h: s.Handler()}, a, clk
}

type reqOpt func(*http.Request)

func noOrigin(r *http.Request)   { r.Header.Del("Origin") }
func noCSRF(r *http.Request)     { r.Header.Del(csrfHeader) }
func host(h string) reqOpt       { return func(r *http.Request) { r.Host = h } }
func header(k, v string) reqOpt  { return func(r *http.Request) { r.Header.Set(k, v) } }
func withOrigin(o string) reqOpt { return func(r *http.Request) { r.Header.Set("Origin", o) } }

func (c *client) do(method, path string, body any, opts ...reqOpt) *httptest.ResponseRecorder {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		if s, ok := body.(string); ok {
			rd = strings.NewReader(s)
		} else {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
	}
	r := httptest.NewRequest(method, "http://"+testHost+path, rd)
	r.Host = testHost
	if method != http.MethodGet {
		r.Header.Set("Origin", testOrigin)
	}
	r.Header.Set("Content-Type", "application/json")
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	if c.csrf != "" {
		r.Header.Set(csrfHeader, c.csrf)
	}
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	return w
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return m
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	m := decodeBody(t, w)
	e, _ := m["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

// bootstrap creates a session and records cookie and CSRF token.
func (c *client) bootstrap() {
	c.t.Helper()
	w := c.do("POST", "/api/session", map[string]string{"launchToken": launch})
	if w.Code != 200 {
		c.t.Fatalf("bootstrap: %d %s", w.Code, w.Body)
	}
	for _, ck := range w.Result().Cookies() {
		if ck.Name == cookieName {
			c.cookie = ck
		}
	}
	c.csrf = decodeBody(c.t, w)["csrfToken"].(string)
}

func (c *client) unlocked() {
	c.t.Helper()
	c.bootstrap()
	w := c.do("POST", "/api/vault/init", map[string]string{"password": masterPW})
	if w.Code != 200 {
		c.t.Fatalf("init: %d %s", w.Code, w.Body)
	}
	if rk, _ := decodeBody(c.t, w)["recoveryKey"].(string); !strings.HasPrefix(rk, "VENR-") {
		c.t.Fatalf("init response lacks a recovery key: %s", w.Body)
	}
}

func TestHostValidation(t *testing.T) {
	c, _, _ := newTestServer(t)
	for _, h := range []string{"evil.example:7420", "127.0.0.1:9999", "localhost", "attacker.localhost:7420"} {
		w := c.do("GET", "/api/session", nil, host(h))
		if w.Code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: got %d, want 421", h, w.Code)
		}
	}
	for _, h := range []string{"127.0.0.1:7420", "localhost:7420", "[::1]:7420"} {
		if w := c.do("GET", "/api/session", nil, host(h)); w.Code != 200 {
			t.Errorf("Host %q: got %d, want 200", h, w.Code)
		}
	}
}

func TestSessionBootstrapProtection(t *testing.T) {
	c, _, _ := newTestServer(t)
	if w := c.do("POST", "/api/session", map[string]string{"launchToken": "wrong"}); w.Code != 401 {
		t.Fatalf("wrong launch token: %d", w.Code)
	}
	if w := c.do("POST", "/api/session", map[string]string{"launchToken": launch}, noOrigin); w.Code != 403 {
		t.Fatalf("missing Origin: %d", w.Code)
	}
	if w := c.do("POST", "/api/session", map[string]string{"launchToken": launch}, withOrigin("http://evil.example")); w.Code != 403 {
		t.Fatalf("hostile Origin: %d", w.Code)
	}
	if w := c.do("POST", "/api/session", map[string]string{"launchToken": launch}, header("Sec-Fetch-Site", "cross-site")); w.Code != 403 {
		t.Fatalf("cross-site fetch: %d", w.Code)
	}
	w := c.do("POST", "/api/session", map[string]string{"launchToken": launch})
	if w.Code != 200 {
		t.Fatalf("valid bootstrap: %d", w.Code)
	}
	ck := w.Result().Cookies()[0]
	if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" {
		t.Fatalf("cookie attributes: %+v", ck)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS must not be enabled")
	}
}

func TestBootstrapThrottled(t *testing.T) {
	c, _, _ := newTestServer(t)
	for i := 0; i < 5; i++ {
		c.do("POST", "/api/session", map[string]string{"launchToken": "wrong"})
	}
	if w := c.do("POST", "/api/session", map[string]string{"launchToken": launch}); w.Code != 429 {
		t.Fatalf("got %d, want 429 after repeated failures", w.Code)
	}
}

func TestCSRFAndOriginOnStateChanges(t *testing.T) {
	c, _, _ := newTestServer(t)
	c.unlocked()
	body := map[string]any{"name": "api"}
	if w := c.do("POST", "/api/projects", body, noCSRF); w.Code != 403 || errCode(t, w) != "csrf" {
		t.Fatalf("missing CSRF: %d %s", w.Code, w.Body)
	}
	if w := c.do("POST", "/api/projects", body, header(csrfHeader, strings.Repeat("0", 64))); w.Code != 403 {
		t.Fatalf("wrong CSRF: %d", w.Code)
	}
	if w := c.do("POST", "/api/projects", body, noOrigin); w.Code != 403 || errCode(t, w) != "forbidden_origin" {
		t.Fatalf("missing Origin: %d", w.Code)
	}
	if w := c.do("POST", "/api/projects", body, withOrigin("http://127.0.0.1:9999")); w.Code != 403 {
		t.Fatalf("other-port Origin: %d", w.Code)
	}
	// Even reads need the CSRF header, so a leaked cookie alone is useless.
	if w := c.do("GET", "/api/projects", nil, noCSRF); w.Code != 403 {
		t.Fatalf("GET without CSRF: %d", w.Code)
	}
	if w := c.do("POST", "/api/projects", body); w.Code != 201 {
		t.Fatalf("valid request: %d %s", w.Code, w.Body)
	}
}

func TestLockedAccessRejected(t *testing.T) {
	c, _, _ := newTestServer(t)
	if w := c.do("GET", "/api/projects", nil); w.Code != 401 || errCode(t, w) != "no_session" {
		t.Fatalf("no session: %d %s", w.Code, w.Body)
	}
	c.unlocked()
	if w := c.do("POST", "/api/vault/lock", nil); w.Code != 200 {
		t.Fatalf("lock: %d", w.Code)
	}
	for _, p := range []struct{ m, path string }{
		{"GET", "/api/projects"}, {"GET", "/api/settings"}, {"POST", "/api/import/preview"},
		{"POST", "/api/variables/abc/reveal"}, {"GET", "/api/projects/x/environments/y/text-values"},
	} {
		if w := c.do(p.m, p.path, map[string]any{}); w.Code != 401 || errCode(t, w) != "locked" {
			t.Errorf("%s %s while locked: %d %s", p.m, p.path, w.Code, w.Body)
		}
	}
}

func TestUnlockAndThrottle(t *testing.T) {
	c, _, _ := newTestServer(t)
	c.unlocked()
	c.do("POST", "/api/vault/lock", nil)
	for i := 0; i < 5; i++ {
		if w := c.do("POST", "/api/vault/unlock", map[string]string{"password": "wrong password!"}); w.Code != 401 || errCode(t, w) != "incorrect_password" {
			t.Fatalf("attempt %d: %d %s", i, w.Code, w.Body)
		}
	}
	w := c.do("POST", "/api/vault/unlock", map[string]string{"password": masterPW})
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("expected throttling, got %d", w.Code)
	}
}

func TestAutoLockAfterInactivity(t *testing.T) {
	c, a, clk := newTestServer(t)
	c.unlocked()
	if err := a.SetAutoLockMinutes(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
	clk.Advance(4 * time.Minute)
	if w := c.do("GET", "/api/projects", nil); w.Code != 200 {
		t.Fatalf("before timeout: %d", w.Code)
	}
	// Polling session state is not activity.
	clk.Advance(3 * time.Minute)
	c.do("GET", "/api/session", nil)
	clk.Advance(3 * time.Minute)
	if w := c.do("GET", "/api/projects", nil); w.Code != 401 || errCode(t, w) != "locked" {
		t.Fatalf("after timeout: %d %s", w.Code, w.Body)
	}
	if m := decodeBody(t, c.do("GET", "/api/session", nil)); m["unlocked"] != false {
		t.Fatalf("session should report locked: %v", m)
	}
}

func TestSecurityHeaders(t *testing.T) {
	c, _, _ := newTestServer(t)
	w := c.do("GET", "/api/session", nil)
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("CSP: %q", w.Header().Get("Content-Security-Policy"))
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control: %q", w.Header().Get("Cache-Control"))
	}
	if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing framing/nosniff headers")
	}
}

func TestRequestSizeLimit(t *testing.T) {
	c, _, _ := newTestServer(t)
	c.unlocked()
	big := `{"name":"` + strings.Repeat("a", maxBodyBytes) + `"}`
	if w := c.do("POST", "/api/projects", big); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d", w.Code)
	}
	huge := map[string]any{"project": "p", "environment": "e", "content": strings.Repeat("A=1\n", 300000)}
	if w := c.do("POST", "/api/import/preview", huge); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized import: %d", w.Code)
	}
}

func TestSensitiveValuesAbsentFromMetadata(t *testing.T) {
	c, _, _ := newTestServer(t)
	c.unlocked()
	c.do("POST", "/api/projects", map[string]any{"name": "api", "environments": []string{"dev"}})
	base := "/api/projects/api/environments/dev"
	w := c.do("POST", base+"/variables", map[string]any{"key": "API_TOKEN", "value": "dummy-secret-value", "type": "secret"})
	if w.Code != 201 || strings.Contains(w.Body.String(), "dummy-secret-value") {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	id := decodeBody(t, w)["variable"].(map[string]any)["id"].(string)
	c.do("POST", base+"/variables", map[string]any{"key": "PORT", "value": "8080", "type": "text"})

	for _, path := range []string{base + "/variables", "/api/projects", "/api/projects/api"} {
		w := c.do("GET", path, nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), "dummy-secret-value") || strings.Contains(w.Body.String(), "8080") {
			t.Fatalf("%s leaked a value: %s", path, w.Body)
		}
	}
	w = c.do("GET", base+"/text-values", nil)
	if !strings.Contains(w.Body.String(), "8080") || strings.Contains(w.Body.String(), "dummy-secret-value") {
		t.Fatalf("text-values must include only text values: %s", w.Body)
	}
	w = c.do("POST", "/api/variables/"+id+"/reveal", nil)
	if decodeBody(t, w)["value"] != "dummy-secret-value" {
		t.Fatalf("reveal: %s", w.Body)
	}
	if w := c.do("POST", "/api/variables/"+id+"/reveal", nil, noCSRF); w.Code != 403 {
		t.Fatalf("reveal without CSRF: %d", w.Code)
	}
	// Duplicate creation is a conflict, not an overwrite.
	if w := c.do("POST", base+"/variables", map[string]any{"key": "API_TOKEN", "value": "x"}); w.Code != 409 {
		t.Fatalf("duplicate create: %d", w.Code)
	}
}

func TestImportPreviewAndCommit(t *testing.T) {
	c, _, _ := newTestServer(t)
	c.unlocked()
	c.do("POST", "/api/projects", map[string]any{"name": "api", "environments": []string{"dev"}})
	content := "A=dummy-a\nB=dummy-b\nbroken line\n"
	w := c.do("POST", "/api/import/preview", map[string]any{"project": "api", "environment": "dev", "content": content})
	m := decodeBody(t, w)
	if w.Code != 200 || m["plan"] != nil || len(m["issues"].([]any)) != 1 || strings.Contains(w.Body.String(), "dummy-a") {
		t.Fatalf("preview with errors: %s", w.Body)
	}
	content = "A=dummy-a\nB=dummy-b\n"
	w = c.do("POST", "/api/import/preview", map[string]any{"project": "api", "environment": "staging", "content": content})
	m = decodeBody(t, w)
	if target := m["target"].(map[string]any); target["environmentExists"] != false {
		t.Fatalf("target: %v", target)
	}
	if strings.Contains(w.Body.String(), "dummy-a") {
		t.Fatal("preview leaked values")
	}
	if w := c.do("POST", "/api/import/commit", map[string]any{"project": "api", "environment": "staging", "content": content}); w.Code != 400 || errCode(t, w) != "target_missing" {
		t.Fatalf("commit without createMissing: %d %s", w.Code, w.Body)
	}
	w = c.do("POST", "/api/import/commit", map[string]any{"project": "api", "environment": "staging", "content": content, "createMissing": true})
	if w.Code != 200 {
		t.Fatalf("commit: %d %s", w.Code, w.Body)
	}
	// Replace requires explicit confirmation.
	w = c.do("POST", "/api/import/commit", map[string]any{"project": "api", "environment": "staging", "content": "A=dummy-a\n", "mode": "replace"})
	if w.Code != 400 || errCode(t, w) != "replace_not_confirmed" {
		t.Fatalf("unconfirmed replace: %d %s", w.Code, w.Body)
	}
	// Conflicts need a resolution.
	w = c.do("POST", "/api/import/commit", map[string]any{"project": "api", "environment": "staging", "content": "A=changed\n"})
	if w.Code != 409 || errCode(t, w) != "unresolved_conflicts" {
		t.Fatalf("unresolved conflicts: %d %s", w.Code, w.Body)
	}
	w = c.do("POST", "/api/import/commit", map[string]any{"project": "api", "environment": "staging", "content": "A=changed\n",
		"resolutions": map[string]string{"A": "overwrite"}})
	if w.Code != 200 {
		t.Fatalf("resolved commit: %d %s", w.Code, w.Body)
	}
	w = c.do("POST", "/api/projects/api/environments/staging/export", nil)
	if !strings.Contains(w.Body.String(), "A=changed") {
		t.Fatalf("export: %s", w.Body)
	}
}

func TestDeleteRequiresConfirmation(t *testing.T) {
	c, _, _ := newTestServer(t)
	c.unlocked()
	c.do("POST", "/api/projects", map[string]any{"name": "api", "environments": []string{"dev"}})
	if w := c.do("DELETE", "/api/projects/api", map[string]string{"confirm": "nope"}); w.Code != 400 {
		t.Fatalf("delete without confirm: %d", w.Code)
	}
	if w := c.do("DELETE", "/api/projects/api", map[string]string{"confirm": "api"}); w.Code != 204 {
		t.Fatalf("delete: %d", w.Code)
	}
}

func TestSPAFallbackWithoutFrontend(t *testing.T) {
	c, _, _ := newTestServer(t)
	if w := c.do("GET", "/projects/x", nil); w.Code != 503 || !strings.Contains(w.Body.String(), "not built") {
		t.Fatalf("missing frontend: %d", w.Code)
	}
	if w := c.do("GET", "/api/nope", nil); w.Code != 404 {
		t.Fatalf("unknown API: %d", w.Code)
	}
}
