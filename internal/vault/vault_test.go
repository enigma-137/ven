package vault

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/enigma-137/ven/internal/storage"
)

// testKDF keeps tests fast while staying inside the accepted bounds.
var testKDF = KDFParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1}

func newTestService(t *testing.T) (*Service, *storage.DB) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewService(db, WithKDFParams(testKDF)), db
}

const pw = "correct horse battery"

func TestInitAndUnlock(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestService(t)

	if _, err := s.Unlock(ctx, []byte(pw)); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("unlock before init: got %v, want ErrNotInitialized", err)
	}
	st, err := s.Status(ctx)
	if err != nil || st.Initialized {
		t.Fatalf("status before init = %+v, %v", st, err)
	}

	k1, err := s.Init(ctx, []byte(pw))
	if err != nil {
		t.Fatal(err)
	}
	nonce, ct, err := k1.Seal([]byte("dummy-value"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}

	k2, err := s.Unlock(ctx, []byte(pw))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := k2.Open(nonce, ct, []byte("aad"))
	if err != nil || string(pt) != "dummy-value" {
		t.Fatalf("decrypt with unlocked key = %q, %v", pt, err)
	}
	if k1.VaultID() != k2.VaultID() || k1.VaultID() == "" {
		t.Fatal("vault IDs should match and be non-empty")
	}

	if _, err := s.Init(ctx, []byte(pw)); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second init: got %v, want ErrAlreadyInitialized", err)
	}
}

func TestIncorrectPasswordRejected(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestService(t)
	if _, err := s.Init(ctx, []byte(pw)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unlock(ctx, []byte("wrong password!!")); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("got %v, want ErrIncorrectPassword", err)
	}
}

func TestPasswordPolicy(t *testing.T) {
	s, _ := newTestService(t)
	if _, err := s.Init(context.Background(), []byte("short")); err == nil {
		t.Fatal("expected short password to be rejected")
	}
	if err := ValidatePassword([]byte{0xff, 0xfe, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'}); err == nil {
		t.Fatal("expected invalid UTF-8 to be rejected")
	}
}

func TestTamperingRejected(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestService(t)
	k, err := s.Init(ctx, []byte(pw))
	if err != nil {
		t.Fatal(err)
	}
	aad := ValueAAD(ValueFormatV1, k.VaultID(), "proj", "env", "var1")
	nonce, ct, err := k.Seal([]byte("dummy-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}

	tampered := bytes.Clone(ct)
	tampered[0] ^= 0x01
	if _, err := k.Open(nonce, tampered, aad); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered ciphertext: got %v, want ErrDecrypt", err)
	}
	badNonce := bytes.Clone(nonce)
	badNonce[0] ^= 0x01
	if _, err := k.Open(badNonce, ct, aad); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered nonce: got %v, want ErrDecrypt", err)
	}
	for name, other := range map[string][]byte{
		"variable": ValueAAD(ValueFormatV1, k.VaultID(), "proj", "env", "var2"),
		"env":      ValueAAD(ValueFormatV1, k.VaultID(), "proj", "env2", "var1"),
		"project":  ValueAAD(ValueFormatV1, k.VaultID(), "proj2", "env", "var1"),
		"vault":    ValueAAD(ValueFormatV1, "other-vault", "proj", "env", "var1"),
		"version":  ValueAAD(2, k.VaultID(), "proj", "env", "var1"),
	} {
		if _, err := k.Open(nonce, ct, other); !errors.Is(err, ErrDecrypt) {
			t.Errorf("wrong %s AAD: got %v, want ErrDecrypt", name, err)
		}
	}
}

func TestAADIsUnambiguous(t *testing.T) {
	a := ValueAAD(1, "v", "ab", "c", "d")
	b := ValueAAD(1, "v", "a", "bc", "d")
	if bytes.Equal(a, b) {
		t.Fatal("length-prefixed AAD must distinguish field boundaries")
	}
}

func TestTamperedKDFMetadataRejected(t *testing.T) {
	ctx := context.Background()
	s, db := newTestService(t)
	if _, err := s.Init(ctx, []byte(pw)); err != nil {
		t.Fatal(err)
	}
	// Changing parameters (still within bounds) breaks the AAD binding.
	if _, err := db.Exec(`UPDATE vault_config SET kdf_iterations = 2`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unlock(ctx, []byte(pw)); err == nil {
		t.Fatal("expected unlock to fail after KDF metadata tampering")
	}
	// Out-of-bounds parameters are refused before running Argon2id.
	if _, err := db.Exec(`UPDATE vault_config SET kdf_memory_kib = 99999999`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unlock(ctx, []byte(pw)); err == nil || errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("expected metadata rejection, got %v", err)
	}
}

func TestChangePasswordPreservesValues(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestService(t)
	k, err := s.Init(ctx, []byte(pw))
	if err != nil {
		t.Fatal(err)
	}
	nonce, ct, _ := k.Seal([]byte("dummy-value"), []byte("aad"))

	if err := s.ChangePassword(ctx, []byte("not the password"), []byte("new password 123")); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("change with wrong current: got %v", err)
	}
	if err := s.ChangePassword(ctx, []byte(pw), []byte("new password 123")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unlock(ctx, []byte(pw)); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("old password should fail, got %v", err)
	}
	k2, err := s.Unlock(ctx, []byte("new password 123"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := k2.Open(nonce, ct, []byte("aad"))
	if err != nil || string(pt) != "dummy-value" {
		t.Fatalf("value after password change = %q, %v", pt, err)
	}
}

func TestDestroyedKeyIsLocked(t *testing.T) {
	s, _ := newTestService(t)
	k, err := s.Init(context.Background(), []byte(pw))
	if err != nil {
		t.Fatal(err)
	}
	k.Destroy()
	if _, _, err := k.Seal([]byte("x"), nil); !errors.Is(err, ErrLocked) {
		t.Fatalf("seal after destroy: got %v", err)
	}
}

func TestNoncesAreFresh(t *testing.T) {
	s, _ := newTestService(t)
	k, _ := s.Init(context.Background(), []byte(pw))
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		n, _, err := k.Seal([]byte("same"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(n)] {
			t.Fatal("nonce reused")
		}
		seen[string(n)] = true
	}
}
