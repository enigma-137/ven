package storage

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
)

func openTemp(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	v1, _ := db.SchemaVersion(context.Background())
	db.Close()
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	v2, _ := db.SchemaVersion(context.Background())
	sub, _ := fs.Sub(migrationFS, "migrations")
	all, err := loadMigrations(sub)
	if err != nil {
		t.Fatal(err)
	}
	latest := all[len(all)-1].version
	if v1 != latest || v2 != latest {
		t.Fatalf("schema versions = %d, %d; want %d, %d", v1, v2, latest, latest)
	}
}

func newProject(slug string) *Project {
	now := Now()
	return &Project{ID: NewID(), Name: slug, Slug: slug, CreatedAt: now, UpdatedAt: now}
}

func newEnv(projectID, slug string) *Environment {
	now := Now()
	return &Environment{ID: NewID(), ProjectID: projectID, Name: slug, Slug: slug, CreatedAt: now, UpdatedAt: now}
}

func newVar(envID, key string) *Variable {
	now := Now()
	return &Variable{ID: NewID(), EnvironmentID: envID, Key: key, Ciphertext: []byte{1}, Nonce: make([]byte, 12),
		EncVersion: 1, DisplayType: "secret", CreatedAt: now, UpdatedAt: now}
}

func TestUniquenessConstraints(t *testing.T) {
	ctx := context.Background()
	db := openTemp(t)

	p := newProject("api")
	if err := InsertProject(ctx, db, p); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(ctx, db, newProject("api")); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate project slug: got %v, want ErrConflict", err)
	}

	e := newEnv(p.ID, "dev")
	if err := InsertEnvironment(ctx, db, e); err != nil {
		t.Fatal(err)
	}
	if err := InsertEnvironment(ctx, db, newEnv(p.ID, "dev")); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate env slug: got %v, want ErrConflict", err)
	}
	// The same environment slug is fine in another project.
	p2 := newProject("web")
	if err := InsertProject(ctx, db, p2); err != nil {
		t.Fatal(err)
	}
	if err := InsertEnvironment(ctx, db, newEnv(p2.ID, "dev")); err != nil {
		t.Fatalf("env slug in other project: %v", err)
	}

	if err := InsertVariable(ctx, db, newVar(e.ID, "TOKEN")); err != nil {
		t.Fatal(err)
	}
	if err := InsertVariable(ctx, db, newVar(e.ID, "TOKEN")); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate key: got %v, want ErrConflict", err)
	}
}

func TestForeignKeysAndCascade(t *testing.T) {
	ctx := context.Background()
	db := openTemp(t)

	if err := InsertEnvironment(ctx, db, newEnv("missing", "dev")); err == nil {
		t.Fatal("expected foreign key violation for environment with unknown project")
	}
	if err := InsertVariable(ctx, db, newVar("missing", "A")); err == nil {
		t.Fatal("expected foreign key violation for variable with unknown environment")
	}

	p := newProject("api")
	e := newEnv(p.ID, "dev")
	v := newVar(e.ID, "A")
	for _, err := range []error{InsertProject(ctx, db, p), InsertEnvironment(ctx, db, e), InsertVariable(ctx, db, v)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := DeleteProject(ctx, db, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := GetEnvironmentByID(ctx, db, e.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("environment should cascade-delete, got %v", err)
	}
	if _, err := GetVariableByID(ctx, db, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("variable should cascade-delete, got %v", err)
	}
}

func TestCheckConstraints(t *testing.T) {
	ctx := context.Background()
	db := openTemp(t)
	p := newProject("api")
	e := newEnv(p.ID, "dev")
	_ = InsertProject(ctx, db, p)
	_ = InsertEnvironment(ctx, db, e)
	v := newVar(e.ID, "A")
	v.DisplayType = "public"
	if err := InsertVariable(ctx, db, v); err == nil {
		t.Fatal("expected check constraint failure for display_type")
	}
	v = newVar(e.ID, "B")
	v.Nonce = []byte{1, 2, 3}
	if err := InsertVariable(ctx, db, v); err == nil {
		t.Fatal("expected check constraint failure for nonce length")
	}
}

func TestSearchEscapesLikeWildcards(t *testing.T) {
	ctx := context.Background()
	db := openTemp(t)
	p := newProject("api")
	e := newEnv(p.ID, "dev")
	_ = InsertProject(ctx, db, p)
	_ = InsertEnvironment(ctx, db, e)
	_ = InsertVariable(ctx, db, newVar(e.ID, "DB_HOST"))
	_ = InsertVariable(ctx, db, newVar(e.ID, "DBXHOST"))
	got, err := ListVariables(ctx, db, e.ID, "db_")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Key != "DB_HOST" {
		t.Fatalf("search db_ = %+v; want only DB_HOST", got)
	}
}
