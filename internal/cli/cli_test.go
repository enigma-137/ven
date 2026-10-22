package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enigma-137/ven/internal/envfile"
	"github.com/enigma-137/ven/internal/vault"
)

var testKDF = vault.KDFParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1}

const masterPW = "dummy master password"

// fakeTerm answers prompts from scripted queues.
type fakeTerm struct {
	interactive bool
	passwords   []string
	lines       []string
	prompts     []string
}

func (f *fakeTerm) Interactive() bool { return f.interactive }

func (f *fakeTerm) ReadPassword(prompt string) ([]byte, error) {
	f.prompts = append(f.prompts, prompt)
	if !f.interactive || len(f.passwords) == 0 {
		return nil, ErrNoTerminal
	}
	p := f.passwords[0]
	f.passwords = f.passwords[1:]
	return []byte(p), nil
}

func (f *fakeTerm) ReadLine(prompt string) (string, error) {
	f.prompts = append(f.prompts, prompt)
	if !f.interactive || len(f.lines) == 0 {
		return "", ErrNoTerminal
	}
	l := f.lines[0]
	f.lines = f.lines[1:]
	return l, nil
}

type result struct {
	code   int
	stdout string
	stderr string
}

type harness struct {
	t     *testing.T
	vault string
	dir   string
}

func newHarness(t *testing.T) *harness {
	dir := t.TempDir()
	return &harness{t: t, vault: filepath.Join(dir, "vault.db"), dir: dir}
}

func (h *harness) run(term *fakeTerm, stdin string, args ...string) result {
	h.t.Helper()
	if term == nil {
		term = &fakeTerm{}
	}
	var out, errb bytes.Buffer
	env := &Env{In: strings.NewReader(stdin), Out: &out, Err: &errb, Term: term}
	kdf := testKDF
	c := &cli{env: env, kdf: &kdf}
	code := c.run(context.Background(), append([]string{"--vault", h.vault}, args...))
	return result{code: code, stdout: out.String(), stderr: errb.String()}
}

func (h *harness) mustRun(term *fakeTerm, stdin string, args ...string) result {
	h.t.Helper()
	r := h.run(term, stdin, args...)
	if r.code != 0 {
		h.t.Fatalf("ven %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), r.code, r.stdout, r.stderr)
	}
	return r
}

func (h *harness) init() {
	h.t.Helper()
	h.mustRun(&fakeTerm{interactive: true, passwords: []string{masterPW, masterPW}}, "", "init")
}

func TestInitAndStatus(t *testing.T) {
	h := newHarness(t)
	r := h.mustRun(nil, "", "status")
	if !strings.Contains(r.stdout, "not initialized") {
		t.Fatalf("status before init: %s", r.stdout)
	}
	// Mismatched confirmation is retried.
	term := &fakeTerm{interactive: true, passwords: []string{masterPW, "different password", masterPW, masterPW}}
	r = h.mustRun(term, "", "init")
	if !strings.Contains(r.stderr, "recovery key") || !strings.Contains(r.stderr, "do not match") {
		t.Fatalf("init stderr: %s", r.stderr)
	}
	if !strings.HasPrefix(r.stdout, "VENR-") {
		t.Fatalf("init stdout should carry the recovery key: %q", r.stdout)
	}
	if r := h.run(&fakeTerm{interactive: true, passwords: []string{masterPW, masterPW}}, "", "init"); r.code != ExitConflict {
		t.Fatalf("second init exit = %d", r.code)
	}
	if r := h.mustRun(nil, "", "status"); !strings.Contains(r.stdout, "initialized, locked") {
		t.Fatalf("status: %s", r.stdout)
	}
}

func TestUninitializedAndWrongPassword(t *testing.T) {
	h := newHarness(t)
	if r := h.run(nil, masterPW+"\n", "--password-stdin", "get", "X", "-p", "a", "-e", "b"); r.code != ExitAuth {
		t.Fatalf("uninitialized exit = %d (%s)", r.code, r.stderr)
	}
	h.init()
	h.mustRun(nil, "", "projects", "create", "api")
	h.mustRun(nil, masterPW+"\ndummy\n", "--password-stdin", "set", "TOKEN", "-p", "api", "-e", "development", "--value-stdin")
}

func TestNonInteractiveRequiresInput(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun(nil, "", "projects", "create", "api")
	// No terminal and no --password-stdin: fail clearly instead of hanging.
	r := h.run(nil, "", "get", "X", "-p", "api", "-e", "development")
	if r.code == 0 {
		t.Fatal("expected failure")
	}
	r = h.run(nil, "", "export", "--stdout")
	if r.code != ExitInputNeeded || !strings.Contains(r.stderr, "--project is required") {
		t.Fatalf("export without flags: %d %s", r.code, r.stderr)
	}
	r = h.run(nil, "", "projects", "delete", "api")
	if r.code != ExitInputNeeded {
		t.Fatalf("delete without --yes: %d", r.code)
	}
}

func TestImportExportWorkflow(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun(nil, "", "projects", "create", "Billing API", "--description", "dummy project")

	envPath := filepath.Join(h.dir, "input.env")
	content := "# dummy credentials only\nexport STRIPE_SECRET_KEY=sk_test_dummy\nPORT=8080\nGREETING=\"hello world\"\nMULTI=\"a\nb\"\n"
	os.WriteFile(envPath, []byte(content), 0o600)

	r := h.mustRun(nil, masterPW+"\n", "--password-stdin", "import", envPath, "-p", "billing-api", "-e", "development")
	if !strings.Contains(r.stderr, "4 created") {
		t.Fatalf("import: %s", r.stderr)
	}
	if strings.Contains(r.stderr, "sk_test_dummy") || strings.Contains(r.stdout, "sk_test_dummy") {
		t.Fatal("import output leaked a value")
	}

	r = h.mustRun(nil, "", "list", "-p", "billing-api", "-e", "development")
	if !strings.Contains(r.stdout, "STRIPE_SECRET_KEY") || strings.Contains(r.stdout, "sk_test_dummy") || strings.Contains(r.stdout, "8080") {
		t.Fatalf("list must mask values: %s", r.stdout)
	}
	if !strings.Contains(r.stdout, "secret") || !strings.Contains(r.stdout, "text") {
		t.Fatalf("list should show types: %s", r.stdout)
	}

	r = h.mustRun(nil, masterPW+"\n", "--password-stdin", "get", "STRIPE_SECRET_KEY", "-p", "billing-api", "-e", "development")
	if r.stdout != "sk_test_dummy" {
		t.Fatalf("get stdout = %q", r.stdout)
	}

	// Export to a file, then refuse to overwrite without --force.
	out := filepath.Join(h.dir, "out.env")
	r = h.mustRun(nil, masterPW+"\n", "--password-stdin", "export", "-p", "billing-api", "-e", "development", "--out", out)
	if r.stdout != "" {
		t.Fatalf("file export wrote to stdout: %q", r.stdout)
	}
	if !strings.Contains(r.stderr, "Variables:    4") || strings.Contains(r.stderr, "sk_test_dummy") {
		t.Fatalf("export preview: %s", r.stderr)
	}
	first, _ := os.ReadFile(out)
	os.WriteFile(out, []byte("SENTINEL=1\n"), 0o600)
	r = h.run(nil, masterPW+"\n", "--password-stdin", "export", "-p", "billing-api", "-e", "development", "--out", out)
	if r.code != ExitConflict {
		t.Fatalf("overwrite without --force: exit %d", r.code)
	}
	if b, _ := os.ReadFile(out); string(b) != "SENTINEL=1\n" {
		t.Fatal("file was overwritten without --force")
	}
	h.mustRun(nil, masterPW+"\n", "--password-stdin", "export", "-p", "billing-api", "-e", "development", "--out", out, "--force")
	if b, _ := os.ReadFile(out); !bytes.Equal(b, first) {
		t.Fatal("--force export differs from first export")
	}

	// --stdout keeps diagnostics on stderr.
	r = h.mustRun(nil, masterPW+"\n", "--password-stdin", "export", "-p", "billing-api", "-e", "development", "--stdout")
	parsed := envfile.Parse([]byte(r.stdout))
	if parsed.HasErrors() || parsed.Map()["MULTI"] != "a\nb" || parsed.Map()["GREETING"] != "hello world" {
		t.Fatalf("stdout export: %q %v", r.stdout, parsed.Issues)
	}
	if strings.Contains(r.stdout, "Project:") {
		t.Fatal("diagnostics leaked to stdout")
	}

	// Reimporting the export changes nothing.
	r = h.mustRun(nil, masterPW+"\n", "--password-stdin", "import", out, "-p", "billing-api", "-e", "development")
	if !strings.Contains(r.stderr, "0 created, 0 updated, 0 kept, 4 unchanged") {
		t.Fatalf("reimport: %s", r.stderr)
	}
}

func TestImportConflictsAndReplace(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun(nil, "", "projects", "create", "api")
	a := filepath.Join(h.dir, "a.env")
	b := filepath.Join(h.dir, "b.env")
	os.WriteFile(a, []byte("A=1\nB=2\n"), 0o600)
	os.WriteFile(b, []byte("A=changed\n"), 0o600)
	h.mustRun(nil, masterPW+"\n", "--password-stdin", "import", a, "-p", "api", "-e", "development")

	// Conflicts need a decision in non-interactive mode.
	r := h.run(nil, masterPW+"\n", "--password-stdin", "import", b, "-p", "api", "-e", "development")
	if r.code != ExitConflict {
		t.Fatalf("conflict exit = %d (%s)", r.code, r.stderr)
	}
	h.mustRun(nil, masterPW+"\n", "--password-stdin", "import", b, "-p", "api", "-e", "development", "--on-conflict", "keep")
	if r := h.mustRun(nil, masterPW+"\n", "--password-stdin", "get", "A", "-p", "api", "-e", "development"); r.stdout != "1" {
		t.Fatalf("keep: A = %q", r.stdout)
	}

	// Interactive: choose overwrite, then confirm.
	term := &fakeTerm{interactive: true, passwords: []string{masterPW}, lines: []string{"o", "y"}}
	h.mustRun(term, "", "import", b, "-p", "api", "-e", "development")
	if r := h.mustRun(nil, masterPW+"\n", "--password-stdin", "get", "A", "-p", "api", "-e", "development"); r.stdout != "changed" {
		t.Fatalf("overwrite: A = %q", r.stdout)
	}

	// Replace needs --yes non-interactively; B survives until confirmed.
	r = h.run(nil, masterPW+"\n", "--password-stdin", "import", b, "-p", "api", "-e", "development", "--replace")
	if r.code != ExitInputNeeded {
		t.Fatalf("replace without --yes: %d %s", r.code, r.stderr)
	}
	// Interactive replace with a wrong confirmation word is cancelled.
	term = &fakeTerm{interactive: true, passwords: []string{masterPW}, lines: []string{"nope"}}
	if r := h.run(term, "", "import", b, "-p", "api", "-e", "development", "--replace"); r.code != ExitCancelled {
		t.Fatalf("cancelled replace exit = %d", r.code)
	}
	if r := h.mustRun(nil, "", "list", "-p", "api", "-e", "development"); !strings.Contains(r.stdout, "B ") {
		t.Fatalf("B removed by unconfirmed replace: %s", r.stdout)
	}
	h.mustRun(nil, masterPW+"\n", "--password-stdin", "import", b, "-p", "api", "-e", "development", "--replace", "--yes")
	if r := h.mustRun(nil, "", "list", "-p", "api", "-e", "development"); strings.Contains(r.stdout, "B ") {
		t.Fatalf("B should be removed: %s", r.stdout)
	}
}

func TestImportMalformedFileReportsLines(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun(nil, "", "projects", "create", "api")
	p := filepath.Join(h.dir, "bad.env")
	os.WriteFile(p, []byte("GOOD=1\nthis line is broken secretvalue\nBAD-KEY=secretvalue2\n"), 0o600)
	r := h.run(nil, masterPW+"\n", "--password-stdin", "import", p, "-p", "api", "-e", "development")
	if r.code == 0 {
		t.Fatal("malformed import should fail")
	}
	if !strings.Contains(r.stderr, "line 2") || !strings.Contains(r.stderr, "line 3") || strings.Contains(r.stderr, "secretvalue") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	if r := h.mustRun(nil, "", "list", "-p", "api", "-e", "development"); strings.Contains(r.stdout, "GOOD") {
		t.Fatal("failed import must not write anything")
	}
}

func TestImportCreatesMissingTarget(t *testing.T) {
	h := newHarness(t)
	h.init()
	p := filepath.Join(h.dir, "x.env")
	os.WriteFile(p, []byte("A=1\n"), 0o600)
	r := h.run(nil, masterPW+"\n", "--password-stdin", "import", p, "-p", "newproj", "-e", "qa")
	if r.code != ExitInputNeeded {
		t.Fatalf("missing target without --create: %d", r.code)
	}
	h.mustRun(nil, masterPW+"\n", "--password-stdin", "import", p, "-p", "newproj", "-e", "qa", "--create")
	if r := h.mustRun(nil, "", "envs", "list", "-p", "newproj"); !strings.Contains(r.stdout, "qa") {
		t.Fatalf("envs: %s", r.stdout)
	}
}

func TestSetUnsetAndPasswordChange(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun(nil, "", "projects", "create", "api", "--envs", "dev")
	term := &fakeTerm{interactive: true, passwords: []string{"dummy-hidden-value", masterPW}}
	r := h.mustRun(term, "", "set", "API_TOKEN", "-p", "api", "-e", "dev")
	if !strings.HasPrefix(term.prompts[0], "Value for API_TOKEN") {
		t.Fatalf("prompts: %v", term.prompts)
	}
	if strings.Contains(r.stderr, "dummy-hidden-value") {
		t.Fatal("set echoed the value")
	}

	term = &fakeTerm{interactive: true, passwords: []string{masterPW, "new dummy password", "new dummy password"}}
	h.mustRun(term, "", "password", "change")
	if r := h.run(nil, masterPW+"\n", "--password-stdin", "get", "API_TOKEN", "-p", "api", "-e", "dev"); r.code != ExitAuth {
		t.Fatalf("old password exit = %d", r.code)
	}
	r = h.mustRun(nil, "new dummy password\n", "--password-stdin", "get", "API_TOKEN", "-p", "api", "-e", "dev")
	if r.stdout != "dummy-hidden-value" {
		t.Fatalf("after password change: %q", r.stdout)
	}
	h.mustRun(nil, "", "unset", "API_TOKEN", "-p", "api", "-e", "dev")
	if r := h.run(nil, "new dummy password\n", "--password-stdin", "get", "API_TOKEN", "-p", "api", "-e", "dev"); r.code != ExitNotFound {
		t.Fatalf("get after unset: %d", r.code)
	}
}

func TestProjectAndEnvironmentManagement(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun(nil, "", "projects", "create", "Web App")
	if r := h.run(nil, "", "projects", "create", "web app"); r.code != ExitConflict {
		t.Fatalf("duplicate project exit = %d", r.code)
	}
	h.mustRun(nil, "", "projects", "rename", "web-app", "Website")
	h.mustRun(nil, "", "projects", "update", "website", "--description", "marketing")
	r := h.mustRun(nil, "", "projects", "list")
	if !strings.Contains(r.stdout, "Website") || !strings.Contains(r.stdout, "marketing") {
		t.Fatalf("list: %s", r.stdout)
	}
	h.mustRun(nil, "", "envs", "create", "Preview", "--project", "website")
	r = h.mustRun(nil, "", "envs", "list", "--project", "website")
	for _, e := range []string{"development", "staging", "production", "preview"} {
		if !strings.Contains(r.stdout, e) {
			t.Fatalf("envs list missing %s: %s", e, r.stdout)
		}
	}
	// Interactive delete requires typing the slug.
	term := &fakeTerm{interactive: true, lines: []string{"wrong"}}
	if r := h.run(term, "", "envs", "delete", "preview", "--project", "website"); r.code != ExitCancelled {
		t.Fatalf("cancelled delete exit = %d", r.code)
	}
	term = &fakeTerm{interactive: true, lines: []string{"preview"}}
	h.mustRun(term, "", "envs", "delete", "preview", "--project", "website")
	h.mustRun(nil, "", "projects", "delete", "website", "--yes")
	if r := h.run(nil, "", "envs", "list", "--project", "website"); r.code != ExitNotFound {
		t.Fatalf("deleted project exit = %d", r.code)
	}
}

func TestExitCodeMapping(t *testing.T) {
	if exitCode(errors.New("x")) != ExitError || exitCode(vault.ErrIncorrectPassword) != ExitAuth || exitCode(ErrCancelled) != ExitCancelled {
		t.Fatal("unexpected exit code mapping")
	}
}

func TestRecoveryKeyReset(t *testing.T) {
	h := newHarness(t)
	r := h.mustRun(&fakeTerm{interactive: true, passwords: []string{masterPW, masterPW}}, "", "init")
	rk := strings.TrimSpace(r.stdout)
	if r := h.mustRun(nil, "", "status"); !strings.Contains(r.stdout, "Recovery key: set") {
		t.Fatalf("status: %s", r.stdout)
	}
	h.mustRun(nil, "", "projects", "create", "api")
	h.mustRun(nil, masterPW+"\ndummy-value\n", "--password-stdin", "set", "TOKEN", "-p", "api", "-e", "development", "--value-stdin")

	if r := h.run(nil, "VENR-WRONG\nnew master password\n", "--password-stdin", "password", "reset"); r.code != ExitUsage {
		t.Fatalf("malformed key: %d %s", r.code, r.stderr)
	}
	h.mustRun(nil, rk+"\nnew master password\n", "--password-stdin", "password", "reset")
	if r := h.run(nil, masterPW+"\n", "--password-stdin", "get", "TOKEN", "-p", "api", "-e", "development"); r.code != ExitAuth {
		t.Fatalf("old password still works: %d", r.code)
	}
	r = h.mustRun(nil, "new master password\n", "--password-stdin", "get", "TOKEN", "-p", "api", "-e", "development")
	if r.stdout != "dummy-value" {
		t.Fatalf("value after reset: %q", r.stdout)
	}

	// A new recovery key replaces the old one.
	if r := h.run(nil, "new master password\n", "--password-stdin", "password", "recovery-key"); r.code != ExitInputNeeded {
		t.Fatalf("replace without --yes: %d", r.code)
	}
	r = h.mustRun(nil, "new master password\n", "--password-stdin", "password", "recovery-key", "--yes")
	rk2 := strings.TrimSpace(r.stdout)
	if rk2 == rk || !strings.HasPrefix(rk2, "VENR-") {
		t.Fatalf("new recovery key %q", rk2)
	}
	if r := h.run(nil, rk+"\nthird master password\n", "--password-stdin", "password", "reset"); r.code != ExitAuth {
		t.Fatalf("old recovery key still works: %d %s", r.code, r.stderr)
	}
}
