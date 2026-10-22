package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enigma-137/ven/internal/envfile"
	"github.com/enigma-137/ven/internal/remote/server"
)

// fakeGitHub implements the parts of GitHub's device flow VEN uses.
type fakeGitHub struct {
	mu      sync.Mutex
	next    string            // handle of the user who will approve the next login
	devices map[string]string // device code -> handle
	tokens  map[string]string // access token -> handle
	n       int
}

func (g *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/login/device/code":
		g.n++
		code := fmt.Sprintf("device-%d", g.n)
		g.devices[code] = g.next
		json.NewEncoder(w).Encode(map[string]any{"device_code": code, "user_code": "ABCD-1234",
			"verification_uri": "https://github.com/login/device", "expires_in": 900, "interval": 0})
	case "/login/oauth/access_token":
		r.ParseForm()
		handle, ok := g.devices[r.Form.Get("device_code")]
		if !ok {
			json.NewEncoder(w).Encode(map[string]string{"error": "expired_token"})
			return
		}
		delete(g.devices, r.Form.Get("device_code"))
		tok := "gho_" + handle
		g.tokens[tok] = handle
		json.NewEncoder(w).Encode(map[string]string{"access_token": tok})
	case "/user":
		handle, ok := g.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		id := 0
		for _, c := range handle {
			id = id*31 + int(c)
		}
		json.NewEncoder(w).Encode(map[string]any{"id": id, "login": handle, "name": strings.ToUpper(handle)})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type remoteEnv struct {
	t      *testing.T
	gh     *fakeGitHub
	url    string
	dbPath string
}

func newRemoteEnv(t *testing.T) *remoteEnv {
	gh := &fakeGitHub{devices: map[string]string{}, tokens: map[string]string{}}
	ghSrv := httptest.NewServer(gh)
	t.Cleanup(ghSrv.Close)
	dbPath := filepath.Join(t.TempDir(), "server.db")
	srv, err := server.New(server.Config{DBPath: dbPath, GitHubClientID: "test-client", GitHubURL: ghSrv.URL, GitHubAPIURL: ghSrv.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &remoteEnv{t: t, gh: gh, url: ts.URL, dbPath: dbPath}
}

// person is one CLI user with their own data directory.
type person struct {
	t      *testing.T
	handle string
	pw     string
	vault  string
}

func (re *remoteEnv) person(handle string) *person {
	return &person{t: re.t, handle: handle, pw: "account password of " + handle, vault: filepath.Join(re.t.TempDir(), "vault.db")}
}

func (p *person) run(term *fakeTerm, stdin string, args ...string) result {
	p.t.Helper()
	if term == nil {
		term = &fakeTerm{}
	}
	var out, errb bytes.Buffer
	env := &Env{In: strings.NewReader(stdin), Out: &out, Err: &errb, Term: term}
	kdf := testKDF
	c := &cli{env: env, kdf: &kdf, sleep: func(context.Context, time.Duration) error { return nil },
		clipboard: func(b []byte) error { out.Write(b); return nil }}
	code := c.run(context.Background(), append([]string{"--vault", p.vault}, args...))
	return result{code: code, stdout: out.String(), stderr: errb.String()}
}

func (p *person) must(stdin string, args ...string) result {
	p.t.Helper()
	r := p.run(nil, stdin, args...)
	if r.code != 0 {
		p.t.Fatalf("[%s] ven %s: exit %d\nstdout: %s\nstderr: %s", p.handle, strings.Join(args, " "), r.code, r.stdout, r.stderr)
	}
	return r
}

// withPW runs a command that needs the account password.
func (p *person) withPW(args ...string) result {
	p.t.Helper()
	return p.must(p.pw+"\n", append([]string{"--password-stdin"}, args...)...)
}

func (p *person) tryPW(args ...string) result {
	p.t.Helper()
	return p.run(nil, p.pw+"\n", append([]string{"--password-stdin"}, args...)...)
}

func (re *remoteEnv) login(p *person) {
	re.t.Helper()
	re.gh.mu.Lock()
	re.gh.next = p.handle
	re.gh.mu.Unlock()
	r := p.withPW("login", "--server", re.url, "--no-browser")
	if !strings.Contains(r.stderr, "Logged in as "+p.handle) || !strings.Contains(r.stderr, "Account key created") {
		re.t.Fatalf("login %s: %s", p.handle, r.stderr)
	}
}

func parseDotenv(t *testing.T, s string) map[string]string {
	t.Helper()
	res := envfile.Parse([]byte(s))
	if res.HasErrors() {
		t.Fatalf("invalid dotenv %q: %v", s, res.Issues)
	}
	return res.Map()
}

func TestHostedTeamWorkflow(t *testing.T) {
	re := newRemoteEnv(t)
	alice, bob, carol := re.person("alice"), re.person("bob"), re.person("carol")
	re.login(alice)

	// Logging in again on the same account reuses the key.
	re.gh.next = "alice"
	if r := alice.must("", "login", "--no-browser"); !strings.Contains(r.stderr, "Account key fingerprint") {
		t.Fatalf("second login: %s", r.stderr)
	}

	r := alice.must("", "remote", "create", "Billing API")
	if !strings.Contains(r.stderr, "alice/billing-api") || !strings.Contains(r.stderr, "production (protected)") {
		t.Fatalf("create: %s", r.stderr)
	}
	ref := "alice/billing-api"

	src := filepath.Join(t.TempDir(), "dev.env")
	os.WriteFile(src, []byte("STRIPE_KEY=sk_test_dummy_secret\nPORT=8080\n"), 0o600)
	r = alice.withPW("push", "-p", ref, "-e", "development", "--from", src, "--yes")
	if !strings.Contains(r.stderr, "+ STRIPE_KEY") || strings.Contains(r.stderr, "sk_test_dummy_secret") {
		t.Fatalf("push output: %s", r.stderr)
	}
	r = alice.withPW("pull", "-p", "billing-api", "-e", "development", "--stdout")
	if m := parseDotenv(t, r.stdout); m["STRIPE_KEY"] != "sk_test_dummy_secret" || m["PORT"] != "8080" {
		t.Fatalf("pull: %q", r.stdout)
	}
	if r := alice.withPW("push", "-p", ref, "-e", "development", "--from", src, "--yes"); !strings.Contains(r.stderr, "up to date") {
		t.Fatalf("no-op push: %s", r.stderr)
	}

	// The server stores no plaintext.
	db, _ := os.ReadFile(re.dbPath)
	wal, _ := os.ReadFile(re.dbPath + "-wal")
	if bytes.Contains(db, []byte("sk_test_dummy_secret")) || bytes.Contains(wal, []byte("sk_test_dummy_secret")) ||
		bytes.Contains(wal, []byte("STRIPE_KEY")) || bytes.Contains(db, []byte("STRIPE_KEY")) {
		t.Fatal("server database contains plaintext values or key names")
	}

	// Share development and production with bob.
	re.login(bob)
	r = alice.withPW("share", "-p", ref, "--to", "bob", "--env", "development,production", "--role", "developer")
	code := strings.TrimSpace(r.stdout)
	if !strings.HasPrefix(code, "ven_inv_") || !strings.Contains(r.stderr, "ven members approve bob") {
		t.Fatalf("share: %q %s", r.stdout, r.stderr)
	}

	// The code is useless to anyone but bob.
	re.login(carol)
	if r := carol.run(nil, "", "join", code, "--yes"); r.code != ExitNotFound {
		t.Fatalf("carol joined with bob's code: %d %s", r.code, r.stderr)
	}
	// A tampered secret is refused.
	bad := code[:len(code)-3] + "AAA"
	if r := bob.run(nil, "", "join", bad, "--yes"); r.code == 0 {
		t.Fatal("tampered invite accepted")
	}

	r = bob.must("", "join", code, "--yes")
	if !strings.Contains(r.stderr, "Joined alice/billing-api as developer") || !strings.Contains(r.stderr, "Waiting for approval: production") {
		t.Fatalf("join: %s", r.stderr)
	}
	if r := bob.run(nil, "", "join", code, "--yes"); r.code != ExitNotFound {
		t.Fatal("invite worked twice")
	}
	r = bob.withPW("pull", "-p", ref, "-e", "development", "--stdout")
	if parseDotenv(t, r.stdout)["STRIPE_KEY"] != "sk_test_dummy_secret" {
		t.Fatalf("bob pull: %q", r.stdout)
	}
	if r := bob.tryPW("pull", "-p", ref, "-e", "production", "--stdout"); r.code != ExitAuth || !strings.Contains(r.stderr, "waiting for approval") {
		t.Fatalf("bob pulled protected env before approval: %d %s", r.code, r.stderr)
	}
	if r := carol.tryPW("pull", "-p", ref, "-e", "development", "--stdout"); r.code != ExitNotFound {
		t.Fatalf("carol can see the project: %d %s", r.code, r.stderr)
	}

	// Approval needs the right fingerprint.
	who := bob.must("", "whoami").stdout
	fp := strings.TrimSpace(strings.SplitN(who, "fingerprint: ", 2)[1])
	if r := alice.tryPW("members", "approve", "bob", "-p", ref, "--fingerprint", "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"); r.code != ExitAuth {
		t.Fatalf("wrong fingerprint approved: %d %s", r.code, r.stderr)
	}
	alice.withPW("members", "approve", "bob", "-p", ref, "--fingerprint", fp)
	bob.withPW("pull", "-p", ref, "-e", "production", "--stdout")
	r = alice.must("", "members", "-p", ref)
	if !strings.Contains(r.stdout, "bob") || strings.Contains(r.stdout, "pending") {
		t.Fatalf("members: %s", r.stdout)
	}

	// Bob (developer) pushes; alice sees it. A stale writer is refused.
	src2 := filepath.Join(t.TempDir(), "dev2.env")
	os.WriteFile(src2, []byte("NEW_FLAG=on\n"), 0o600)
	bob.withPW("push", "-p", ref, "-e", "development", "--from", src2, "--merge", "--yes")
	r = alice.withPW("pull", "-p", ref, "-e", "development", "--stdout")
	if m := parseDotenv(t, r.stdout); m["NEW_FLAG"] != "on" || m["STRIPE_KEY"] != "sk_test_dummy_secret" {
		t.Fatalf("merged pull: %q", r.stdout)
	}

	// A read-only service token for CI.
	r = alice.withPW("tokens", "create", "-p", ref, "--name", "ci", "--env", "development")
	token := strings.TrimSpace(r.stdout)
	if !strings.HasPrefix(token, "ven_st_") {
		t.Fatalf("token: %q", r.stdout)
	}
	ci := re.person("ci")
	t.Setenv(EnvServer, re.url)
	t.Setenv(EnvToken, token)
	r = ci.must("", "pull", "--stdout")
	if parseDotenv(t, r.stdout)["NEW_FLAG"] != "on" {
		t.Fatalf("token pull: %q", r.stdout)
	}
	if r := ci.run(nil, "", "push", "--from", src, "--yes"); r.code != ExitUsage {
		t.Fatal("token push allowed")
	}
	os.Unsetenv(EnvToken)

	// Removing bob rotates the keys he held; the token keeps working.
	r = alice.withPW("members", "remove", "bob", "-p", ref, "--yes")
	if !strings.Contains(r.stderr, "Rotated the key for development") || !strings.Contains(r.stderr, "Rotated the key for production") {
		t.Fatalf("remove: %s", r.stderr)
	}
	if r := bob.tryPW("pull", "-p", ref, "-e", "development", "--stdout"); r.code != ExitNotFound {
		t.Fatalf("bob still has access: %d %s", r.code, r.stderr)
	}
	r = alice.withPW("pull", "-p", ref, "-e", "development", "--stdout")
	if parseDotenv(t, r.stdout)["STRIPE_KEY"] != "sk_test_dummy_secret" {
		t.Fatalf("pull after rotation: %q", r.stdout)
	}
	t.Setenv(EnvToken, token)
	ci.must("", "pull", "--stdout")
	os.Unsetenv(EnvToken)

	// Revoking the token rotates again and locks the token out.
	alice.withPW("tokens", "revoke", "ci", "-p", ref)
	t.Setenv(EnvToken, token)
	if r := ci.run(nil, "", "pull", "--stdout"); r.code != ExitAuth {
		t.Fatalf("revoked token works: %d %s", r.code, r.stderr)
	}
	os.Unsetenv(EnvToken)

	r = alice.must("", "audit", "-p", ref)
	for _, action := range []string{"project.create", "environment.push", "invite.create", "invite.accept", "member.approve",
		"token.pull", "member.remove", "environment.rotate", "token.revoke"} {
		if !strings.Contains(r.stdout, action) {
			t.Fatalf("audit lacks %s:\n%s", action, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "sk_test_dummy_secret") {
		t.Fatal("audit leaked a value")
	}
}

func TestHostedLinkRunAndEnv(t *testing.T) {
	re := newRemoteEnv(t)
	alice := re.person("alice")
	re.login(alice)
	alice.must("", "remote", "create", "web", "--envs", "development")
	src := filepath.Join(t.TempDir(), "in.env")
	os.WriteFile(src, []byte("GREETING=\"it's here\"\n"), 0o600)
	alice.withPW("push", "-p", "web", "-e", "development", "--from", src, "--yes")

	dir := t.TempDir()
	t.Chdir(dir)
	os.WriteFile(".gitignore", []byte("node_modules"), 0o644)
	alice.must("", "link", "web")
	if b, _ := os.ReadFile(".gitignore"); string(b) != "node_modules\n.env\n" {
		t.Fatalf(".gitignore = %q", b)
	}

	// Flags come from .ven.json.
	alice.withPW("pull")
	if b, _ := os.ReadFile(".env"); parseDotenv(t, string(b))["GREETING"] != "it's here" {
		t.Fatalf(".env = %q", b)
	}
	if r := alice.tryPW("pull"); r.code != ExitConflict {
		t.Fatalf("overwrite without --force: %d", r.code)
	}

	r := alice.withPW("shellenv", "--shell", "posix")
	if r.stdout != `export GREETING='it'\''s here'`+"\n" {
		t.Fatalf("env posix: %q", r.stdout)
	}
	r = alice.withPW("shellenv", "--shell", "powershell")
	if r.stdout != `$env:GREETING = 'it''s here'`+"\n" {
		t.Fatalf("env powershell: %q", r.stdout)
	}
	if r := alice.withPW("copy", "GREETING"); !strings.HasPrefix(r.stdout, "it's here") {
		t.Fatalf("copy: %q", r.stdout)
	}

	if runtime.GOOS != "windows" {
		r = alice.withPW("run", "--", "sh", "-c", `printf %s "$GREETING"`)
		if r.stdout != "it's here" {
			t.Fatalf("run stdout: %q", r.stdout)
		}
		if r := alice.tryPW("run", "--", "sh", "-c", "exit 7"); r.code != 7 || strings.Contains(r.stderr, "error:") {
			t.Fatalf("run exit code: %d %s", r.code, r.stderr)
		}
	}
}

func TestHostedPublishDeleteLogout(t *testing.T) {
	re := newRemoteEnv(t)
	alice := re.person("alice")
	// A local vault for alice with one project.
	alice.must("dummy master\n", "--password-stdin", "init")
	alice.must("", "projects", "create", "api", "--envs", "development")
	alice.must("dummy master\nvalue-1\n", "--password-stdin", "set", "API_TOKEN", "-p", "api", "-e", "development", "--value-stdin")
	re.login(alice)
	// --password-stdin supplies the local master password for publish.
	r := alice.must("dummy master\n", "--password-stdin", "remote", "publish", "api")
	if !strings.Contains(r.stderr, "Published api as alice/api (1 environment(s) with values)") {
		t.Fatalf("publish: %s", r.stderr)
	}
	r = alice.withPW("pull", "-p", "alice/api", "-e", "development", "--stdout")
	if parseDotenv(t, r.stdout)["API_TOKEN"] != "value-1" {
		t.Fatalf("published pull: %q", r.stdout)
	}
	if r := alice.must("", "remote", "list"); !strings.Contains(r.stdout, "alice/api") || !strings.Contains(r.stdout, "owner") {
		t.Fatalf("remote list: %s", r.stdout)
	}
	if r := alice.run(nil, "", "remote", "delete", "alice/api"); r.code != ExitInputNeeded {
		t.Fatalf("delete without --yes: %d", r.code)
	}
	alice.must("", "remote", "delete", "alice/api", "--yes")
	if r := alice.tryPW("pull", "-p", "alice/api", "-e", "development", "--stdout"); r.code != ExitNotFound {
		t.Fatalf("deleted project still readable: %d", r.code)
	}
	if r := alice.must("", "logout"); !strings.Contains(r.stderr, "Logged out") {
		t.Fatal(r.stderr)
	}
	if r := alice.run(nil, "", "remote", "list"); r.code != ExitAuth {
		t.Fatalf("after logout: %d", r.code)
	}
}

func TestParseTTL(t *testing.T) {
	for in, want := range map[string]time.Duration{"30d": 30 * 24 * time.Hour, "12h": 12 * time.Hour, "90m": 90 * time.Minute} {
		if d, never, err := parseTTL(in); err != nil || never || d != want {
			t.Fatalf("%s: %v %v %v", in, d, never, err)
		}
	}
	if _, never, err := parseTTL("never"); err != nil || !never {
		t.Fatal("never")
	}
	for _, bad := range []string{"", "0d", "-1d", "3x", "1.5d", "d"} {
		if _, _, err := parseTTL(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestHostedAccountKeyReset(t *testing.T) {
	re := newRemoteEnv(t)
	alice, bob := re.person("alice"), re.person("bob")
	re.login(alice)
	re.login(bob)
	alice.must("", "remote", "create", "api", "--envs", "development")
	src := filepath.Join(t.TempDir(), "in.env")
	os.WriteFile(src, []byte("TOKEN=dummy-reset\n"), 0o600)
	alice.withPW("push", "-p", "api", "-e", "development", "--from", src, "--yes")
	code := strings.TrimSpace(alice.withPW("share", "-p", "api", "--to", "bob", "--env", "development").stdout)
	bob.must("", "join", code, "--yes")
	oldFP := bob.must("", "whoami").stdout

	// Bob forgot his account password.
	re.gh.next = "bob"
	if r := bob.run(nil, "new password for bob\n", "--password-stdin", "login", "--reset-key"); r.code != ExitInputNeeded {
		t.Fatalf("reset without confirmation: %d %s", r.code, r.stderr)
	}
	re.gh.next = "bob"
	bob.pw = "new password for bob"
	bob.withPW("login", "--reset-key", "--yes")
	if bob.must("", "whoami").stdout == oldFP {
		t.Fatal("fingerprint did not change")
	}
	if r := bob.tryPW("pull", "-p", "alice/api", "-e", "development", "--stdout"); r.code != ExitAuth {
		t.Fatalf("access survived a key reset: %d %s", r.code, r.stderr)
	}

	// Alice's next pull rotates the key; re-sharing restores bob's access.
	if r := alice.withPW("pull", "-p", "api", "-e", "development", "--stdout"); !strings.Contains(r.stderr, "Rotated the key") {
		t.Fatalf("no rotation after reset: %s", r.stderr)
	}
	code = strings.TrimSpace(alice.withPW("share", "-p", "api", "--to", "bob", "--env", "development").stdout)
	bob.must("", "join", code, "--yes")
	if r := bob.withPW("pull", "-p", "alice/api", "-e", "development", "--stdout"); parseDotenv(t, r.stdout)["TOKEN"] != "dummy-reset" {
		t.Fatalf("pull after re-share: %q", r.stdout)
	}
	if r := alice.must("", "audit", "-p", "api"); !strings.Contains(r.stdout, "member.key_reset") {
		t.Fatalf("audit: %s", r.stdout)
	}
}
