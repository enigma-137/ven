package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enigma-137/ven/internal/e2e"
	"github.com/enigma-137/ven/internal/remote/api"
	"github.com/enigma-137/ven/internal/remote/client"
	"github.com/enigma-137/ven/internal/vault"
)

var testKDF = vault.KDFParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1}

// fakeGitHub approves every device login as the handle in next.
type fakeGitHub struct {
	mu   sync.Mutex
	next string
}

func (g *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/login/device/code":
		json.NewEncoder(w).Encode(map[string]any{"device_code": "dc-" + g.next, "user_code": "X", "verification_uri": "u", "interval": 0, "expires_in": 60})
	case "/login/oauth/access_token":
		r.ParseForm()
		json.NewEncoder(w).Encode(map[string]string{"access_token": "tok-" + strings.TrimPrefix(r.Form.Get("device_code"), "dc-")})
	case "/user":
		h := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
		json.NewEncoder(w).Encode(map[string]any{"id": len(h)*1000 + int(h[0]), "login": h})
	}
}

type testServer struct {
	t   *testing.T
	srv *Server
	url string
	gh  *fakeGitHub
	mu  sync.Mutex
	now time.Time
}

func newTestServer(t *testing.T) *testServer {
	ts := &testServer{t: t, gh: &fakeGitHub{}, now: time.Now().UTC()}
	gh := httptest.NewServer(ts.gh)
	t.Cleanup(gh.Close)
	srv, err := New(Config{DBPath: filepath.Join(t.TempDir(), "s.db"), GitHubClientID: "x", GitHubURL: gh.URL, GitHubAPIURL: gh.URL,
		Now: func() time.Time { ts.mu.Lock(); defer ts.mu.Unlock(); return ts.now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	ts.srv, ts.url = srv, hs.URL
	return ts
}

func (ts *testServer) advance(d time.Duration) {
	ts.mu.Lock()
	ts.now = ts.now.Add(d)
	ts.mu.Unlock()
}

// login creates a user with an account key and returns a client.
func (ts *testServer) login(handle string) (*client.Client, *api.Me) {
	ts.t.Helper()
	ctx := context.Background()
	ts.gh.mu.Lock()
	ts.gh.next = handle
	ts.gh.mu.Unlock()
	cl := client.New(ts.url)
	cl.Now = func() time.Time { ts.mu.Lock(); defer ts.mu.Unlock(); return ts.now }
	ds, err := cl.DeviceStart(ctx, "github")
	if err != nil {
		ts.t.Fatal(err)
	}
	sess, err := cl.DevicePoll(ctx, "github", ds.DeviceCode)
	if err != nil {
		ts.t.Fatal(err)
	}
	cl.Account = &client.Account{Server: ts.url, Session: sess}
	priv, _ := e2e.GenerateKey()
	me, _ := cl.Me(ctx)
	wk, _ := e2e.WrapPrivateKey(priv, []byte("pw"), me.ID, testKDF)
	if err := cl.SetKey(ctx, api.SetKeyRequest{PublicKey: priv.PublicKey().Bytes(), WrappedPrivateKey: *wk}); err != nil {
		ts.t.Fatal(err)
	}
	me, _ = cl.Me(ctx)
	return cl, me
}

func mustCode(t *testing.T, err error, code string) {
	t.Helper()
	if !client.IsCode(err, code) {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func createProject(t *testing.T, cl *client.Client, me *api.Me, name string, envs ...string) *api.Project {
	t.Helper()
	pid, _ := e2e.NewID()
	req := api.CreateProjectRequest{ID: pid, Name: name}
	for _, n := range envs {
		id, _ := e2e.NewID()
		k, _ := e2e.NewEnvKey()
		sealed, _ := e2e.SealEnvKey(me.PublicKey, k, pid, id, 1, e2e.PrincipalUser, me.ID)
		req.Environments = append(req.Environments, api.CreateEnvironmentRequest{ID: id, Name: n, SealedKey: sealed})
	}
	p, err := cl.CreateProject(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRefreshRotationAndReplay(t *testing.T) {
	ts := newTestServer(t)
	ctx := context.Background()
	cl, _ := ts.login("alice")
	old := *cl.Account.Session

	// Expired access token: the client refreshes transparently.
	ts.advance(AccessTokenTTL + time.Minute)
	if _, err := cl.Me(ctx); err != nil {
		t.Fatal(err)
	}
	if cl.Account.Session.RefreshToken == old.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}

	// Replaying the old refresh token revokes the whole session.
	thief := client.New(ts.url)
	thief.Account = &client.Account{Session: &old}
	thief.Now = cl.Now
	if _, err := thief.Me(ctx); err == nil {
		t.Fatal("replayed refresh token worked")
	}
	cl.Account.Session.AccessExpiresAt = time.Time{} // force a refresh
	if _, err := cl.Me(ctx); err == nil {
		t.Fatal("session survived a refresh token replay")
	}
}

func TestSetKeyOnce(t *testing.T) {
	ts := newTestServer(t)
	cl, me := ts.login("alice")
	priv, _ := e2e.GenerateKey()
	wk, _ := e2e.WrapPrivateKey(priv, []byte("pw"), me.ID, testKDF)
	err := cl.SetKey(context.Background(), api.SetKeyRequest{PublicKey: priv.PublicKey().Bytes(), WrappedPrivateKey: *wk})
	mustCode(t, err, api.CodeConflict)
}

func TestPermissionsAndStaleWrites(t *testing.T) {
	ts := newTestServer(t)
	ctx := context.Background()
	alice, aliceMe := ts.login("alice")
	bob, _ := ts.login("bob")
	p := createProject(t, alice, aliceMe, "api", "development")
	ref := p.Ref()
	env := p.Environments[0]

	// Non-members get 404, not 403.
	_, err := bob.Project(ctx, ref)
	mustCode(t, err, api.CodeNotFound)
	_, err = bob.Environment(ctx, ref, "development")
	mustCode(t, err, api.CodeNotFound)

	// Stale base revision is refused.
	put := func(base int) error {
		_, err := alice.PutContent(ctx, ref, "development", api.PutContentRequest{BaseRevision: base, KeyVersion: env.KeyVersion,
			Content: api.Content{Nonce: make([]byte, 12), Ciphertext: make([]byte, 32)}})
		return err
	}
	if err := put(0); err != nil {
		t.Fatal(err)
	}
	mustCode(t, put(0), api.CodeStale)

	// Rotation must cover exactly the current recipients.
	_, err = alice.Rotate(ctx, ref, "development", api.RotateRequest{FromKeyVersion: 1, BaseRevision: 1,
		Content: &api.Content{Nonce: make([]byte, 12), Ciphertext: make([]byte, 32)}})
	mustCode(t, err, api.CodeStale)

	// An invite cannot carry a key for a protected environment or grant owner.
	prodID, _ := e2e.NewID()
	k, _ := e2e.NewEnvKey()
	sealed, _ := e2e.SealEnvKey(aliceMe.PublicKey, k, p.ID, prodID, 1, e2e.PrincipalUser, aliceMe.ID)
	if _, err := alice.CreateEnvironment(ctx, ref, api.CreateEnvironmentRequest{ID: prodID, Name: "production", SealedKey: sealed}); err != nil {
		t.Fatal(err)
	}
	inviteID, _ := e2e.NewID()
	secret, _ := e2e.NewSecret()
	ipriv, _ := secret.PrivateKey()
	auth, _ := secret.AuthKey()
	inv := api.CreateInviteRequest{ID: inviteID, Handle: "bob", Role: api.RoleOwner, EnvironmentIDs: []string{prodID},
		PublicKey: ipriv.PublicKey().Bytes(), AuthHash: e2e.AuthHash(auth)}
	_, err = alice.CreateInvite(ctx, ref, inv)
	mustCode(t, err, api.CodeInvalid)
	inv.Role = api.RoleViewer
	inv.Keys = []api.SealedKey{{EnvironmentID: prodID, PrincipalType: e2e.PrincipalInvite, PrincipalID: inviteID, KeyVersion: 1, SealedKey: sealed}}
	_, err = alice.CreateInvite(ctx, ref, inv)
	mustCode(t, err, api.CodeInvalid)

	// A viewer cannot push or invite.
	inv.Keys = nil
	if _, err := alice.CreateInvite(ctx, ref, inv); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.AcceptInvite(ctx, inviteID, api.AcceptInviteRequest{AuthKey: auth}); err != nil {
		t.Fatal(err)
	}
	_, err = bob.PutContent(ctx, ref, "production", api.PutContentRequest{Content: api.Content{Nonce: make([]byte, 12), Ciphertext: make([]byte, 32)}})
	mustCode(t, err, api.CodeForbidden)
	inv.ID, _ = e2e.NewID()
	_, err = bob.CreateInvite(ctx, ref, inv)
	mustCode(t, err, api.CodeForbidden)
	_, err = bob.Environment(ctx, ref, "production")
	mustCode(t, err, api.CodeForbidden)
	mustCode(t, bob.RemoveMember(ctx, ref, "alice"), api.CodeForbidden)
}

func TestMembershipExpiry(t *testing.T) {
	ts := newTestServer(t)
	ctx := context.Background()
	alice, aliceMe := ts.login("alice")
	bob, bobMe := ts.login("bob")
	p := createProject(t, alice, aliceMe, "api", "development")
	env := p.Environments[0]
	ref := p.Ref()

	// Invite bob with a 1-hour membership and a real key.
	inviteID, _ := e2e.NewID()
	secret, _ := e2e.NewSecret()
	ipriv, _ := secret.PrivateKey()
	auth, _ := secret.AuthKey()
	// The key's value does not matter to the server; any key will do.
	k, _ := e2e.NewEnvKey()
	sealedInv, _ := e2e.SealEnvKey(ipriv.PublicKey().Bytes(), k, p.ID, env.ID, 1, e2e.PrincipalInvite, inviteID)
	exp := ts.now.Add(time.Hour)
	if _, err := alice.CreateInvite(ctx, ref, api.CreateInviteRequest{ID: inviteID, Handle: "bob", Role: api.RoleViewer,
		EnvironmentIDs: []string{env.ID}, MemberExpiresAt: &exp, PublicKey: ipriv.PublicKey().Bytes(), AuthHash: e2e.AuthHash(auth),
		Keys: []api.SealedKey{{EnvironmentID: env.ID, PrincipalType: e2e.PrincipalInvite, PrincipalID: inviteID, KeyVersion: 1, SealedKey: sealedInv}}}); err != nil {
		t.Fatal(err)
	}
	// Opening with a wrong auth key looks like a missing invite.
	_, err := bob.OpenInvite(ctx, inviteID, []byte("wrong"))
	mustCode(t, err, api.CodeNotFound)
	sealedBob, _ := e2e.SealEnvKey(bobMe.PublicKey, k, p.ID, env.ID, 1, e2e.PrincipalUser, bobMe.ID)
	if _, err := bob.AcceptInvite(ctx, inviteID, api.AcceptInviteRequest{AuthKey: auth,
		Keys: []api.SealedKey{{EnvironmentID: env.ID, PrincipalType: e2e.PrincipalUser, PrincipalID: bobMe.ID, KeyVersion: 1, SealedKey: sealedBob}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Environment(ctx, ref, "development"); err != nil {
		t.Fatal(err)
	}

	ts.advance(2 * time.Hour)
	bob.Account.Session.AccessExpiresAt = ts.now.Add(time.Hour) // keep the session itself valid
	_, err = bob.Environment(ctx, ref, "development")
	mustCode(t, err, api.CodeNotFound)
	if err := ts.srv.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	p2, err := alice.Project(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if !p2.Environments[0].NeedsRotation {
		t.Fatal("expired member did not flag rotation")
	}
	_, err = alice.PutContent(ctx, ref, "development", api.PutContentRequest{BaseRevision: 0, KeyVersion: 1,
		Content: api.Content{Nonce: make([]byte, 12), Ciphertext: make([]byte, 32)}})
	mustCode(t, err, api.CodeRotationRequired)
}

func TestRateLimit(t *testing.T) {
	ts := newTestServer(t)
	cl := client.New(ts.url)
	var err error
	for i := 0; i < 40; i++ {
		_, err = cl.DevicePoll(context.Background(), "github", fmt.Sprintf("bad-%d", i))
		if client.IsCode(err, api.CodeRateLimited) {
			return
		}
	}
	t.Fatalf("no rate limit after 40 polls: %v", err)
}

func TestTrustProxy(t *testing.T) {
	s := &Server{cfg: Config{TrustProxy: true}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")
	if ip := s.clientIP(r); ip != "203.0.113.9" {
		t.Fatalf("ip = %s", ip)
	}
	r.RemoteAddr = "198.51.100.1:5000" // not loopback: header ignored
	if ip := s.clientIP(r); ip != "198.51.100.1" {
		t.Fatalf("ip = %s", ip)
	}
}

func TestLandingPage(t *testing.T) {
	ts := newTestServer(t)
	for path, want := range map[string]int{"/": 200, "/assets/site.css": 200, "/assets/": 404, "/nope": 404} {
		resp, err := http.Get(ts.url + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s: %d, want %d", path, resp.StatusCode, want)
		}
		if want == 200 && !strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'self'") {
			t.Fatalf("%s: CSP %q", path, resp.Header.Get("Content-Security-Policy"))
		}
	}
}
