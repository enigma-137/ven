package vault

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRecoveryKeyResetsPassword(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestService(t)
	if err := s.ResetPassword(ctx, "VENR-AAAA", []byte("new password 123")); err == nil {
		t.Fatal("reset on an uninitialized vault succeeded")
	}
	k, err := s.Init(ctx, []byte(pw))
	if err != nil {
		t.Fatal(err)
	}
	nonce, ct, _ := k.Seal([]byte("dummy value"), []byte("aad"))
	if has, _ := s.HasRecoveryKey(ctx); has {
		t.Fatal("new vault already has a recovery key")
	}
	_, other, _ := NewRecoveryKey(VaultRecoveryPrefix)
	if err := s.ResetPassword(ctx, other, []byte("new password 123")); !errors.Is(err, ErrNoRecoveryKey) {
		t.Fatalf("reset without recovery key: %v", err)
	}

	rk, err := s.CreateRecoveryKey(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	k.Destroy()
	if !strings.HasPrefix(rk, "VENR-") || len(strings.Split(rk, "-")) != 9 {
		t.Fatalf("recovery key format %q", rk)
	}
	if has, _ := s.HasRecoveryKey(ctx); !has {
		t.Fatal("recovery key not stored")
	}

	if err := s.ResetPassword(ctx, other, []byte("new password 123")); !errors.Is(err, ErrIncorrectRecoveryKey) {
		t.Fatalf("wrong recovery key: %v", err)
	}
	if err := s.ResetPassword(ctx, rk, []byte("short")); err == nil {
		t.Fatal("weak new password accepted")
	}
	// Lower case, spaces and no dashes are accepted.
	messy := strings.ToLower(strings.ReplaceAll(rk, "-", " "))
	if err := s.ResetPassword(ctx, messy, []byte("new password 123")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unlock(ctx, []byte(pw)); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatal("old password still works")
	}
	k2, err := s.Unlock(ctx, []byte("new password 123"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := k2.Open(nonce, ct, []byte("aad")); err != nil || !bytes.Equal(got, []byte("dummy value")) {
		t.Fatalf("values lost after reset: %v", err)
	}

	// Replacing the recovery key invalidates the old one.
	rk2, err := s.CreateRecoveryKey(ctx, k2)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ResetPassword(ctx, rk, []byte("another password 1")); !errors.Is(err, ErrIncorrectRecoveryKey) {
		t.Fatalf("old recovery key still works: %v", err)
	}
	if err := s.ResetPassword(ctx, rk2, []byte("another password 1")); err != nil {
		t.Fatal(err)
	}
}

func TestParseRecoveryKey(t *testing.T) {
	secret, printable, _ := NewRecoveryKey("VENA")
	got, err := ParseRecoveryKey("VENA", " "+printable+"\n")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("parse: %v", err)
	}
	for _, bad := range []string{"", "VENR-" + printable[5:], "VENA-AAAA", printable + "AAAA", "VENA-!!!!"} {
		if _, err := ParseRecoveryKey("VENA", bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
