package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func git(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestGuard(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	h := newHarness(t)
	h.init()
	h.mustRun(nil, "", "projects", "create", "api", "--envs", "development")
	const secret = "sk_live_51HdummyGuardValue"
	envPath := filepath.Join(h.dir, "in.env")
	os.WriteFile(envPath, []byte("STRIPE_SECRET_KEY="+secret+"\nPORT=8080\nAPP_NAME=billing-service\n"), 0o600)
	// Importing teaches guard the secret values (no separate index step).
	h.mustRun(nil, masterPW+"\n", "--password-stdin", "import", envPath, "-p", "api", "-e", "development")
	if r := h.mustRun(nil, "", "guard", "status"); !strings.Contains(r.stdout, "Secret values known: 1") || !strings.Contains(r.stdout, "local:api/development") {
		t.Fatalf("status after import: %s", r.stdout)
	}
	if b, _ := os.ReadFile(filepath.Join(h.dir, "guard.json")); strings.Contains(string(b), secret) {
		t.Fatal("guard.json stores the value")
	}

	repo := t.TempDir()
	t.Chdir(repo)
	git(t, "init", "-q")
	if r := h.run(nil, "", "guard", "install"); r.code != 0 {
		t.Fatalf("install: %d %s", r.code, r.stderr)
	}
	hook, _ := os.ReadFile(filepath.Join(repo, ".git", "hooks", "pre-commit"))
	if !strings.Contains(string(hook), hookMarker) || !strings.Contains(string(hook), "guard scan --staged") || !strings.Contains(string(hook), "--vault") {
		t.Fatalf("hook: %s", hook)
	}

	// Clean change passes.
	os.WriteFile("main.go", []byte("package main\n"), 0o644)
	git(t, "add", "main.go")
	h.mustRun(nil, "", "guard", "scan", "--staged")

	// A stored secret pasted into a config file is blocked, masked.
	os.WriteFile("config.js", []byte("module.exports = {\n  stripe: '"+secret+"',\n  port: 8080,\n};\n"), 0o644)
	os.WriteFile(".env", []byte("STRIPE_SECRET_KEY="+secret+"\n"), 0o600)
	git(t, "add", "config.js", ".env")
	r := h.run(nil, "", "guard", "scan", "--staged")
	if r.code != ExitError || !strings.Contains(r.stderr, "config.js:2") || !strings.Contains(r.stderr, "STRIPE_SECRET_KEY") ||
		!strings.Contains(r.stderr, ".env") || !strings.Contains(r.stderr, "blocked this commit") {
		t.Fatalf("staged scan: %d\n%s", r.code, r.stderr)
	}
	if strings.Contains(r.stderr, secret) || strings.Contains(r.stdout, secret) {
		t.Fatal("scan output leaked the secret")
	}
	if strings.Contains(r.stderr, "8080") && strings.Contains(r.stderr, "PORT") {
		t.Fatal("non-secret value flagged")
	}

	// Folder scan: .env counts only when Git does not ignore it.
	git(t, "reset", "-q")
	if r := h.run(nil, "", "guard", "scan"); r.code != ExitError || !strings.Contains(r.stderr, ".env") || !strings.Contains(r.stderr, "config.js:2") {
		t.Fatalf("folder scan: %d %s", r.code, r.stderr)
	}
	os.WriteFile(".gitignore", []byte(".env\n"), 0o644)
	os.Remove("config.js")
	h.mustRun(nil, "", "guard", "scan")

	// History scan finds a secret committed earlier.
	os.WriteFile("leak.txt", []byte("token "+secret+"\n"), 0o644)
	git(t, "add", "leak.txt")
	git(t, "commit", "-q", "--no-verify", "-m", "oops")
	if r := h.run(nil, "", "guard", "scan", "--history"); r.code != ExitError || !strings.Contains(r.stderr, "leak.txt:1") || !strings.Contains(r.stderr, "Rotate") {
		t.Fatalf("history scan: %d %s", r.code, r.stderr)
	}

	// An unrelated existing hook is not overwritten without --force.
	h.mustRun(nil, "", "guard", "uninstall")
	if _, err := os.Stat(filepath.Join(repo, ".git", "hooks", "pre-commit")); !os.IsNotExist(err) {
		t.Fatal("hook not removed")
	}
	os.WriteFile(filepath.Join(repo, ".git", "hooks", "pre-commit"), []byte("#!/bin/sh\nnpm test\n"), 0o755)
	if r := h.run(nil, "", "guard", "install"); r.code != ExitConflict {
		t.Fatalf("install over a foreign hook: %d", r.code)
	}
	h.mustRun(nil, "", "guard", "install", "--force")
	if b, _ := os.ReadFile(filepath.Join(repo, ".git", "hooks", "pre-commit.bak")); !strings.Contains(string(b), "npm test") {
		t.Fatal("old hook not backed up")
	}

	// Explicit re-index works too.
	h.mustRun(nil, masterPW+"\n", "--password-stdin", "guard", "index", "--local")
}

func TestGuardLearnsFromPull(t *testing.T) {
	re := newRemoteEnv(t)
	alice := re.person("alice")
	re.login(alice)
	alice.must("", "remote", "create", "web", "--envs", "development")
	src := filepath.Join(t.TempDir(), "in.env")
	os.WriteFile(src, []byte("API_TOKEN=tok_dummy_hosted_123\n"), 0o600)
	alice.withPW("push", "-p", "web", "-e", "development", "--from", src, "--yes")
	if r := alice.must("", "guard", "status"); !strings.Contains(r.stdout, "hosted:alice/web/development") || !strings.Contains(r.stdout, "known: 1") {
		t.Fatalf("status after push: %s", r.stdout)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "settings.py"), []byte("TOKEN = 'tok_dummy_hosted_123'\n"), 0o644)
	if r := alice.run(nil, "", "guard", "scan", dir); r.code != ExitError || !strings.Contains(r.stderr, "settings.py:1") || !strings.Contains(r.stderr, "alice/web/development") {
		t.Fatalf("scan: %d %s", r.code, r.stderr)
	}
}
