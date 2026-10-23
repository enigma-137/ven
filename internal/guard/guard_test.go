package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secret = "sk_test_51HdummyDummyDummy"

func newIndex(t *testing.T) *Index {
	t.Helper()
	ix, err := Load(filepath.Join(t.TempDir(), "guard.json"))
	if err != nil {
		t.Fatal(err)
	}
	ix.Replace("local:api/development", []Value{
		{Name: "STRIPE_KEY", Value: secret},
		{Name: "DATABASE_URL", Value: "postgres://app:hunter2hunter2@db:5432/app"},
		{Name: "SHORT", Value: "abc"},
	})
	return ix
}

func TestScanLine(t *testing.T) {
	ix := newIndex(t)
	if ix.Len() != 2 {
		t.Fatalf("indexed %d values, want 2 (short value skipped)", ix.Len())
	}
	for _, line := range []string{
		`const key = "` + secret + `";`,
		`STRIPE=` + secret,
		`stripe: ` + secret,
		`{"k": "` + secret + `"}`,
		`the key is ` + secret + `.`,
		`url = postgres://app:hunter2hunter2@db:5432/app`,
	} {
		hits := ix.scanLine(line)
		if len(hits) != 1 {
			t.Fatalf("%q: %d hits", line, len(hits))
		}
		if m := mask(line, hits); strings.Contains(m, secret) || strings.Contains(m, "hunter2hunter2") {
			t.Fatalf("mask leaked the value: %q", m)
		}
	}
	for _, line := range []string{"nothing here", secret + "X", "x" + secret, "abc"} {
		if hits := ix.scanLine(line); len(hits) != 0 {
			t.Fatalf("%q: false positive", line)
		}
	}
}

func TestPersistAndReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.json")
	ix, _ := Load(path)
	ix.Replace("hosted:o/p/dev", []Value{{Name: "TOKEN", Value: secret}})
	if err := ix.Save(); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("guard.json mode %v", info.Mode())
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), secret) {
		t.Fatal("index stores plaintext")
	}
	ix2, err := Load(path)
	if err != nil || ix2.Len() != 1 || len(ix2.scanLine(secret)) != 1 {
		t.Fatalf("reload: %v %d", err, ix2.Len())
	}
	// A new value replaces the old one for that source.
	ix2.Replace("hosted:o/p/dev", []Value{{Name: "TOKEN", Value: "rotated-value-123"}})
	if len(ix2.scanLine(secret)) != 0 || len(ix2.scanLine("rotated-value-123")) != 1 {
		t.Fatal("replace did not drop the old value")
	}
	ix2.Forget("hosted:")
	if ix2.Len() != 0 {
		t.Fatal("forget")
	}
}

func TestIsEnvFile(t *testing.T) {
	for p, want := range map[string]bool{
		".env": true, "app/.env.local": true, ".env.production": true, ".env.development.local": true, ".env.staging": true,
		"prod.env": true, "secrets.env": true, "config/.ENV": true, ".env-local": true, ".env_prod": true, "env.local": true,
		"env.production.local": true,
		".env.example": false, ".env.sample": false, ".env.template": false, ".env.local.example": false,
		".env.production.sample": false, ".env-example": false, "env.example": false, ".env.dist": false,
		"env.go": false, "env.ts": false, "environment.ts": false, ".envrc": false, "README.md": false, "dotenv.md": false,
	} {
		if IsEnvFile(p) != want {
			t.Errorf("IsEnvFile(%q) = %v", p, !want)
		}
	}
}

func TestScanDiff(t *testing.T) {
	ix := newIndex(t)
	diff := strings.Join([]string{
		"\x00commit 0123456789abcdef0123",
		"diff --git a/.env b/.env",
		"new file mode 100644",
		"index 0000000..1111111",
		"--- /dev/null",
		"+++ b/.env",
		"@@ -0,0 +1 @@",
		"+STRIPE_KEY=" + secret,
		"diff --git a/src/config.js b/src/config.js",
		"index 1111111..2222222 100644",
		"--- a/src/config.js",
		"+++ b/src/config.js",
		"@@ -10,0 +11,2 @@",
		"+const ok = 1;",
		"+const key = '" + secret + "';",
		"diff --git a/.env.example b/.env.example",
		"--- a/.env.example",
		"+++ b/.env.example",
		"@@ -1 +1 @@",
		"-STRIPE_KEY=",
		"+STRIPE_KEY=changeme",
		"diff --git a/old.txt b/prod.env",
		"similarity index 100%",
		"rename from old.txt",
		"rename to prod.env",
	}, "\n")
	got := ix.ScanDiff(diff)
	if len(got) != 3 {
		t.Fatalf("findings: %+v", got)
	}
	if got[0].Kind != KindEnvFile || got[0].File != ".env" || got[0].Commit != "0123456789ab" {
		t.Fatalf("env file finding: %+v", got[0])
	}
	if got[1].Kind != KindSecret || got[1].File != "src/config.js" || got[1].Line != 12 || got[1].Name != "STRIPE_KEY" {
		t.Fatalf("secret finding: %+v", got[1])
	}
	if strings.Contains(got[1].Preview, secret) {
		t.Fatal("preview leaked the value")
	}
	if got[2].Kind != KindEnvFile || got[2].File != "prod.env" {
		t.Fatalf("rename finding: %+v", got[2])
	}
}
