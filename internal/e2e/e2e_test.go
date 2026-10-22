package e2e

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/enigma-137/ven/internal/vault"
)

var testKDF = vault.KDFParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1}

func TestSealRoundTripAndBinding(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envKey, _ := NewEnvKey()
	sealed, err := SealEnvKey(priv.PublicKey().Bytes(), envKey, "p1", "e1", 1, PrincipalUser, "u1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenEnvKey(priv, sealed, "p1", "e1", 1, PrincipalUser, "u1")
	if err != nil || !bytes.Equal(got, envKey) {
		t.Fatalf("open: %v", err)
	}
	// Any change of context must fail.
	for _, c := range []struct {
		p, e  string
		v     int
		ty, i string
	}{
		{"p2", "e1", 1, PrincipalUser, "u1"},
		{"p1", "e2", 1, PrincipalUser, "u1"},
		{"p1", "e1", 2, PrincipalUser, "u1"},
		{"p1", "e1", 1, PrincipalToken, "u1"},
		{"p1", "e1", 1, PrincipalUser, "u2"},
	} {
		if _, err := OpenEnvKey(priv, sealed, c.p, c.e, c.v, c.ty, c.i); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("context %+v opened: %v", c, err)
		}
	}
	other, _ := GenerateKey()
	if _, err := OpenEnvKey(other, sealed, "p1", "e1", 1, PrincipalUser, "u1"); !errors.Is(err, ErrDecrypt) {
		t.Fatal("wrong recipient opened the key")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := OpenEnvKey(priv, sealed, "p1", "e1", 1, PrincipalUser, "u1"); !errors.Is(err, ErrDecrypt) {
		t.Fatal("tampered ciphertext opened")
	}
	if _, err := OpenSealed(priv, []byte("short"), nil); !errors.Is(err, ErrDecrypt) {
		t.Fatal("short input opened")
	}
}

func TestEnvBlob(t *testing.T) {
	k, _ := NewEnvKey()
	nonce, ct, err := SealEnv(k, []byte("A=1\n"), "p", "e", 3, 7)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := OpenEnv(k, nonce, ct, "p", "e", 3, 7); err != nil || string(pt) != "A=1\n" {
		t.Fatalf("open: %q %v", pt, err)
	}
	// An old revision replayed under a new revision number fails.
	if _, err := OpenEnv(k, nonce, ct, "p", "e", 3, 8); !errors.Is(err, ErrDecrypt) {
		t.Fatal("revision not bound")
	}
}

func TestWrapPrivateKey(t *testing.T) {
	priv, _ := GenerateKey()
	pub := priv.PublicKey().Bytes()
	w, err := WrapPrivateKey(priv, []byte("account password"), "u1", testKDF)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapPrivateKey(w, []byte("account password"), "u1", pub)
	if err != nil || !bytes.Equal(got.Bytes(), priv.Bytes()) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := UnwrapPrivateKey(w, []byte("wrong password"), "u1", pub); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := UnwrapPrivateKey(w, []byte("account password"), "u2", pub); err == nil {
		t.Fatal("other user id accepted")
	}
	other, _ := GenerateKey()
	if _, err := UnwrapPrivateKey(w, []byte("account password"), "u1", other.PublicKey().Bytes()); err == nil {
		t.Fatal("substituted public key accepted")
	}
	w.Memory = 4 * 1024 * 1024
	if _, err := UnwrapPrivateKey(w, []byte("account password"), "u1", pub); err == nil || errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("out-of-bounds KDF must be rejected before deriving: %v", err)
	}
}

func TestCredentials(t *testing.T) {
	s, _ := NewSecret()
	id, _ := NewID()
	cred := FormatCredential(InvitePrefix, id, s)
	gotID, gotS, err := ParseCredential(InvitePrefix, " "+cred+"\n")
	if err != nil || gotID != id || !bytes.Equal(gotS, s) {
		t.Fatalf("parse: %v", err)
	}
	if _, _, err := ParseCredential(TokenPrefix, cred); err == nil {
		t.Fatal("wrong prefix accepted")
	}
	if _, _, err := ParseCredential(InvitePrefix, InvitePrefix+id+"_abc"); err == nil {
		t.Fatal("short secret accepted")
	}
	a1, _ := s.AuthKey()
	if !CheckAuth(a1, AuthHash(a1)) {
		t.Fatal("auth check failed")
	}
	other, _ := NewSecret()
	a2, _ := other.AuthKey()
	if CheckAuth(a2, AuthHash(a1)) {
		t.Fatal("other secret authenticated")
	}
	// The auth key and the private key are independent derivations.
	pk, _ := s.PrivateKey()
	if bytes.Equal(pk.Bytes(), a1) {
		t.Fatal("auth key equals private key")
	}
}

func TestFingerprint(t *testing.T) {
	a, _ := GenerateKey()
	b, _ := GenerateKey()
	fa := Fingerprint(a.PublicKey().Bytes())
	if len(strings.Split(fa, "-")) != 6 || fa != Fingerprint(a.PublicKey().Bytes()) || fa == Fingerprint(b.PublicKey().Bytes()) {
		t.Fatalf("fingerprint %q", fa)
	}
}
