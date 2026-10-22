package variables_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/enigma-137/ven/internal/app"
	"github.com/enigma-137/ven/internal/envfile"
	"github.com/enigma-137/ven/internal/projects"
	"github.com/enigma-137/ven/internal/storage"
	"github.com/enigma-137/ven/internal/variables"
	"github.com/enigma-137/ven/internal/vault"
)

var testKDF = vault.KDFParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1}

type fixture struct {
	app   *app.App
	key   *vault.Key
	envID string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	a, err := app.Open(filepath.Join(t.TempDir(), "vault.db"), vault.WithKDFParams(testKDF))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	k, err := a.Vault.Init(ctx, []byte("dummy master password"))
	if err != nil {
		t.Fatal(err)
	}
	_, envs, err := a.Projects.Create(ctx, projects.CreateInput{Name: "Demo API", Environments: projects.DefaultEnvironments})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{app: a, key: k, envID: envs[0].ID}
}

func parse(t *testing.T, src string) []envfile.Entry {
	t.Helper()
	r := envfile.Parse([]byte(src))
	if r.HasErrors() {
		t.Fatal(r.Errors())
	}
	return r.Entries
}

func values(t *testing.T, f *fixture) map[string]string {
	t.Helper()
	entries, err := f.app.Variables.Entries(context.Background(), f.key, f.envID)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, e := range entries {
		m[e.Key] = e.Value
	}
	return m
}

func TestSetGetAndEncryptionAtRest(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	v, created, err := f.app.Variables.Set(ctx, f.key, f.envID, variables.SetInput{Key: "API_TOKEN", Value: "dummy-token-123"})
	if err != nil || !created {
		t.Fatalf("set: %v created=%v", err, created)
	}
	if v.Type != variables.TypeSecret {
		t.Fatalf("API_TOKEN classified as %s", v.Type)
	}
	_, got, err := f.app.Variables.Get(ctx, f.key, f.envID, "API_TOKEN")
	if err != nil || got != "dummy-token-123" {
		t.Fatalf("get = %q, %v", got, err)
	}
	// The stored blob must not contain the plaintext.
	var ct []byte
	if err := f.app.DB.QueryRow(`SELECT value_ciphertext FROM variables WHERE key = 'API_TOKEN'`).Scan(&ct); err != nil {
		t.Fatal(err)
	}
	if string(ct) == "dummy-token-123" || len(ct) < 16 {
		t.Fatal("value is not encrypted at rest")
	}
	// Text-typed values are encrypted too.
	if _, _, err := f.app.Variables.Set(ctx, f.key, f.envID, variables.SetInput{Key: "PORT", Value: "8080"}); err != nil {
		t.Fatal(err)
	}
	var n int
	f.app.DB.QueryRow(`SELECT COUNT(*) FROM variables WHERE value_ciphertext = CAST('8080' AS BLOB)`).Scan(&n)
	if n != 0 {
		t.Fatal("text value stored in plaintext")
	}
}

func TestSwappedCiphertextRejected(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	f.app.Variables.Set(ctx, f.key, f.envID, variables.SetInput{Key: "A", Value: "dummy-a"})
	f.app.Variables.Set(ctx, f.key, f.envID, variables.SetInput{Key: "B", Value: "dummy-b"})
	// Copy A's ciphertext onto B: AAD binds the record ID, so B must fail.
	if _, err := f.app.DB.Exec(`UPDATE variables SET value_ciphertext = (SELECT value_ciphertext FROM variables WHERE key='A'),
		value_nonce = (SELECT value_nonce FROM variables WHERE key='A') WHERE key = 'B'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.app.Variables.Get(ctx, f.key, f.envID, "B"); !errors.Is(err, vault.ErrDecrypt) {
		t.Fatalf("got %v, want ErrDecrypt", err)
	}
}

func TestUpdateRenameKeepsValue(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	v, _, _ := f.app.Variables.Set(ctx, f.key, f.envID, variables.SetInput{Key: "OLD", Value: "dummy"})
	newKey := "NEW_NAME"
	if _, err := f.app.Variables.Update(ctx, f.key, v.ID, variables.UpdateInput{Key: &newKey}); err != nil {
		t.Fatal(err)
	}
	if _, got, err := f.app.Variables.Get(ctx, f.key, f.envID, "NEW_NAME"); err != nil || got != "dummy" {
		t.Fatalf("after rename: %q, %v", got, err)
	}
}

func TestPasswordChangePreservesVariables(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	f.app.Variables.Set(ctx, f.key, f.envID, variables.SetInput{Key: "DB_PASSWORD", Value: "dummy-pass"})
	if err := f.app.Vault.ChangePassword(ctx, []byte("dummy master password"), []byte("another dummy password")); err != nil {
		t.Fatal(err)
	}
	k2, err := f.app.Vault.Unlock(ctx, []byte("another dummy password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, got, err := f.app.Variables.Get(ctx, k2, f.envID, "DB_PASSWORD"); err != nil || got != "dummy-pass" {
		t.Fatalf("after password change: %q, %v", got, err)
	}
}

func TestImportPlanAndConflicts(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	f.app.Variables.Set(ctx, f.key, f.envID, variables.SetInput{Key: "SAME", Value: "1"})
	f.app.Variables.Set(ctx, f.key, f.envID, variables.SetInput{Key: "DIFF", Value: "old"})
	f.app.Variables.Set(ctx, f.key, f.envID, variables.SetInput{Key: "ONLY_EXISTING", Value: "x"})

	entries := parse(t, "SAME=1\nDIFF=new\nFRESH_TOKEN=dummy\n")
	plan, err := f.app.Variables.PlanImport(ctx, f.key, f.envID, entries, variables.ModeMerge)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Counts != (variables.PlanCounts{New: 1, Changed: 1, Unchanged: 1}) {
		t.Fatalf("counts = %+v", plan.Counts)
	}

	// Without a decision, conflicts block the import.
	if _, err := f.app.Variables.ApplyImport(ctx, f.key, f.envID, entries, variables.ImportOptions{}); !errors.Is(err, variables.ErrUnresolvedConflicts) {
		t.Fatalf("got %v, want ErrUnresolvedConflicts", err)
	}
	if values(t, f)["FRESH_TOKEN"] != "" {
		t.Fatal("failed import must not create variables")
	}

	// Keep the existing value.
	res, err := f.app.Variables.ApplyImport(ctx, f.key, f.envID, entries, variables.ImportOptions{OnConflict: variables.Keep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 1 || res.Kept != 1 || res.Unchanged != 1 {
		t.Fatalf("keep result = %+v", res)
	}
	got := values(t, f)
	if got["DIFF"] != "old" || got["FRESH_TOKEN"] != "dummy" || got["ONLY_EXISTING"] != "x" {
		t.Fatalf("after keep: %v", got)
	}

	// Per-key overwrite.
	res, err = f.app.Variables.ApplyImport(ctx, f.key, f.envID, entries, variables.ImportOptions{
		OnConflict: variables.Keep, Resolutions: map[string]variables.Resolution{"DIFF": variables.Overwrite}})
	if err != nil || res.Updated != 1 {
		t.Fatalf("overwrite: %+v, %v", res, err)
	}
	if values(t, f)["DIFF"] != "new" {
		t.Fatal("DIFF should be overwritten")
	}
}

func TestImportReplaceRequiresConfirmation(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	f.app.Variables.Set(ctx, f.key, f.envID, variables.SetInput{Key: "STALE", Value: "x"})
	entries := parse(t, "A=1\n")
	plan, _ := f.app.Variables.PlanImport(ctx, f.key, f.envID, entries, variables.ModeReplace)
	if plan.Counts.Removed != 1 {
		t.Fatalf("plan = %+v", plan.Counts)
	}
	_, err := f.app.Variables.ApplyImport(ctx, f.key, f.envID, entries, variables.ImportOptions{Mode: variables.ModeReplace})
	if !errors.Is(err, variables.ErrReplaceNotConfirmed) {
		t.Fatalf("got %v", err)
	}
	if _, ok := values(t, f)["STALE"]; !ok {
		t.Fatal("unconfirmed replace removed data")
	}
	res, err := f.app.Variables.ApplyImport(ctx, f.key, f.envID, entries, variables.ImportOptions{Mode: variables.ModeReplace, ConfirmReplace: true})
	if err != nil || res.Removed != 1 || res.Created != 1 {
		t.Fatalf("replace: %+v, %v", res, err)
	}
	if got := values(t, f); len(got) != 1 || got["A"] != "1" {
		t.Fatalf("after replace: %v", got)
	}
}

func TestImportRollbackOnFailure(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	f.app.Variables.Set(ctx, f.key, f.envID, variables.SetInput{Key: "EXISTING", Value: "before"})
	entries := parse(t, "EXISTING=after\nA=1\nB=2\nC=3\n")

	restore := variables.SetApplyHook(func(step int) error {
		if step == 3 {
			return errors.New("injected failure")
		}
		return nil
	})
	_, err := f.app.Variables.ApplyImport(ctx, f.key, f.envID, entries, variables.ImportOptions{OnConflict: variables.Overwrite})
	restore()
	if err == nil {
		t.Fatal("expected injected failure")
	}
	got := values(t, f)
	if len(got) != 1 || got["EXISTING"] != "before" {
		t.Fatalf("partial import persisted: %v", got)
	}
}

func TestImportRejectsInvalidEntries(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	bad := []envfile.Entry{{Key: "A", Value: "1"}, {Key: "A", Value: "2"}}
	if _, err := f.app.Variables.ApplyImport(ctx, f.key, f.envID, bad, variables.ImportOptions{}); err == nil {
		t.Fatal("duplicate keys must be rejected")
	}
	bad = []envfile.Entry{{Key: "1BAD", Value: "1"}}
	if _, err := f.app.Variables.PlanImport(ctx, f.key, f.envID, bad, variables.ModeMerge); err == nil {
		t.Fatal("invalid key must be rejected")
	}
}

func TestExportReimportRoundTrip(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	src := "PLAIN=value\nSPACES='a b c'\nMULTI=\"line1\nline2\"\nQUOTES=\"it's \\\"quoted\\\"\"\nDOLLAR='${NOT_EXPANDED}'\nEMPTY=\nUNI=日本語\n"
	entries := parse(t, src)
	if _, err := f.app.Variables.ApplyImport(ctx, f.key, f.envID, entries, variables.ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	out, n, err := f.app.Variables.Export(ctx, f.key, f.envID)
	if err != nil || n != len(entries) {
		t.Fatalf("export: n=%d err=%v", n, err)
	}
	r := envfile.Parse(out)
	if r.HasErrors() {
		t.Fatal(r.Errors())
	}
	want := envfile.Parse([]byte(src)).Map()
	got := r.Map()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q", k, got[k], v)
		}
	}

	// Reimporting the export is a no-op.
	plan, err := f.app.Variables.PlanImport(ctx, f.key, f.envID, r.Entries, variables.ModeMerge)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Counts.Unchanged != len(entries) || plan.Counts.New+plan.Counts.Changed != 0 {
		t.Fatalf("reimport plan = %+v", plan.Counts)
	}
}

func TestDeleteProjectCascades(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	f.app.Variables.Set(ctx, f.key, f.envID, variables.SetInput{Key: "A", Value: "1"})
	if _, err := f.app.Projects.Delete(ctx, "demo-api"); err != nil {
		t.Fatal(err)
	}
	var n int
	f.app.DB.QueryRow(`SELECT COUNT(*) FROM variables`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d variables remain", n)
	}
	if _, err := f.app.Projects.Resolve(ctx, "demo-api"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"API_KEY": "secret", "STRIPE_SECRET_KEY": "secret", "DB_PASSWORD": "secret", "GITHUB_TOKEN": "secret",
		"DATABASE_URL": "secret", "REDIS_URL": "secret", "PORT": "text", "NODE_ENV": "text", "LOG_LEVEL": "text",
		"PUBLIC_SITE_URL": "text", "NEXT_PUBLIC_API_BASE": "text", "SOMETHING_ODD": "secret", "KEYBOARD_LAYOUT": "secret",
		"FEATURE_FLAGS_ENABLED": "text", "SESSION_SECRET": "secret",
	}
	for key, want := range cases {
		if got, _ := variables.Classify(key); got != want {
			t.Errorf("Classify(%s) = %s, want %s", key, got, want)
		}
	}
}
