// Package e2e holds the end-to-end encryption used by hosted projects.
//
// The server only ever sees ciphertext. Each environment has a random
// 256-bit key that encrypts the environment's dotenv content as one blob.
// That key is sealed to every principal allowed to read the environment:
//
//   - users, whose X25519 private key is wrapped with their account
//     password (Argon2id, same parameters and bounds as the local vault);
//   - invites and service tokens, whose X25519 private key is derived from a
//     random secret that only exists inside the invite code or token string.
//
// Sealing uses an ephemeral X25519 key, HKDF-SHA256 and AES-256-GCM. All
// associated data binds the ciphertext to its project, environment, key
// version and recipient, so the server cannot move ciphertext around.
package e2e

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/enigma-137/ven/internal/vault"
)

const (
	// KeySize is the X25519 key and environment key length in bytes.
	KeySize = 32
	// SecretSize is the length of invite and token secrets in bytes.
	SecretSize = 32

	// FormatVersion is bound into every associated data string.
	FormatVersion = 1

	sealedOverhead = KeySize + vault.NonceSize + 16
)

// ErrDecrypt is returned when anything fails to authenticate.
var ErrDecrypt = vault.ErrDecrypt

// ErrIncorrectPassword is returned when the account password does not
// unwrap the private key.
var ErrIncorrectPassword = errors.New("incorrect account password")

// Principal types an environment key can be sealed to.
const (
	PrincipalUser   = "user"
	PrincipalInvite = "invite"
	PrincipalToken  = "token"
)

// GenerateKey returns a new X25519 private key.
func GenerateKey() (*ecdh.PrivateKey, error) {
	b, err := vault.RandomBytes(KeySize)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(b)
	return ecdh.X25519().NewPrivateKey(b)
}

// ParsePublicKey validates a raw X25519 public key.
func ParsePublicKey(b []byte) (*ecdh.PublicKey, error) {
	if len(b) != KeySize {
		return nil, errors.New("public key must be 32 bytes")
	}
	return ecdh.X25519().NewPublicKey(b)
}

// Fingerprint is a short code people compare out of band to make sure a
// public key really belongs to the person they think: 120 bits of
// SHA-256, base32, in six groups of four.
func Fingerprint(pub []byte) string {
	sum := sha256.Sum256(append([]byte("ven/fingerprint\x00"), pub...))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:15])
	groups := make([]string, 0, 6)
	for i := 0; i < len(enc); i += 4 {
		groups = append(groups, enc[i:i+4])
	}
	return strings.Join(groups, "-")
}

// NewEnvKey returns a random environment key.
func NewEnvKey() ([]byte, error) { return vault.RandomBytes(KeySize) }

// EnvKeyAAD binds a sealed environment key to its environment, key version
// and recipient.
func EnvKeyAAD(projectID, envID string, keyVersion int, principalType, principalID string) []byte {
	return vault.NewAAD("ven/env-key").
		U32(FormatVersion).
		Str(projectID).
		Str(envID).
		U32(uint32(keyVersion)).
		Str(principalType).
		Str(principalID)
}

// EnvBlobAAD binds encrypted environment content to its environment, key
// version and revision.
func EnvBlobAAD(projectID, envID string, keyVersion, revision int) []byte {
	return vault.NewAAD("ven/env-blob").
		U32(FormatVersion).
		Str(projectID).
		Str(envID).
		U32(uint32(keyVersion)).
		U32(uint32(revision))
}

// SealTo encrypts plaintext so only the holder of pub's private key can
// read it. Output: ephemeral public key || nonce || ciphertext.
func SealTo(pub []byte, plaintext, aad []byte) ([]byte, error) {
	recipient, err := ParsePublicKey(pub)
	if err != nil {
		return nil, err
	}
	eph, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(recipient)
	if err != nil {
		return nil, err
	}
	ephPub := eph.PublicKey().Bytes()
	key, err := sealKey(shared, ephPub, pub)
	vault.Wipe(shared)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(key)
	nonce, ct, err := vault.Encrypt(key, plaintext, aad)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(ephPub)+len(nonce)+len(ct))
	out = append(out, ephPub...)
	out = append(out, nonce...)
	return append(out, ct...), nil
}

// OpenSealed reverses SealTo.
func OpenSealed(priv *ecdh.PrivateKey, sealed, aad []byte) ([]byte, error) {
	if priv == nil || len(sealed) < sealedOverhead {
		return nil, ErrDecrypt
	}
	ephPub := sealed[:KeySize]
	nonce := sealed[KeySize : KeySize+vault.NonceSize]
	ct := sealed[KeySize+vault.NonceSize:]
	eph, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		return nil, ErrDecrypt
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, ErrDecrypt
	}
	key, err := sealKey(shared, ephPub, priv.PublicKey().Bytes())
	vault.Wipe(shared)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(key)
	return vault.Decrypt(key, nonce, ct, aad)
}

func sealKey(shared, ephPub, recipientPub []byte) ([]byte, error) {
	salt := make([]byte, 0, 2*KeySize)
	salt = append(append(salt, ephPub...), recipientPub...)
	return hkdf.Key(sha256.New, shared, salt, "ven/seal/v1", vault.KeySize)
}

// SealEnvKey seals an environment key to a principal.
func SealEnvKey(pub, envKey []byte, projectID, envID string, keyVersion int, principalType, principalID string) ([]byte, error) {
	return SealTo(pub, envKey, EnvKeyAAD(projectID, envID, keyVersion, principalType, principalID))
}

// OpenEnvKey opens an environment key sealed with SealEnvKey.
func OpenEnvKey(priv *ecdh.PrivateKey, sealed []byte, projectID, envID string, keyVersion int, principalType, principalID string) ([]byte, error) {
	k, err := OpenSealed(priv, sealed, EnvKeyAAD(projectID, envID, keyVersion, principalType, principalID))
	if err != nil {
		return nil, err
	}
	if len(k) != KeySize {
		vault.Wipe(k)
		return nil, ErrDecrypt
	}
	return k, nil
}

// SealEnv encrypts dotenv content for one revision of an environment.
func SealEnv(envKey, content []byte, projectID, envID string, keyVersion, revision int) (nonce, ciphertext []byte, err error) {
	return vault.Encrypt(envKey, content, EnvBlobAAD(projectID, envID, keyVersion, revision))
}

// OpenEnv decrypts content sealed with SealEnv.
func OpenEnv(envKey, nonce, ciphertext []byte, projectID, envID string, keyVersion, revision int) ([]byte, error) {
	return vault.Decrypt(envKey, nonce, ciphertext, EnvBlobAAD(projectID, envID, keyVersion, revision))
}

// WrappedPrivateKey is a user's private key encrypted with their account
// password. It is stored on the server so a second device can log in.
type WrappedPrivateKey struct {
	Version     int    `json:"version"`
	Memory      uint32 `json:"kdf_memory_kib"`
	Iterations  uint32 `json:"kdf_iterations"`
	Parallelism uint8  `json:"kdf_parallelism"`
	Salt        []byte `json:"salt"`
	Nonce       []byte `json:"nonce"`
	Ciphertext  []byte `json:"ciphertext"`
}

// Params returns the Argon2id parameters the key was wrapped with.
func (w *WrappedPrivateKey) Params() vault.KDFParams {
	return vault.KDFParams{Memory: w.Memory, Iterations: w.Iterations, Parallelism: w.Parallelism}
}

func accountKeyAAD(userID string, w *WrappedPrivateKey, pub []byte) []byte {
	return vault.NewAAD("ven/account-key").
		U32(uint32(w.Version)).
		Str(userID).
		Str("argon2id").
		U32(w.Memory).
		U32(w.Iterations).
		U32(uint32(w.Parallelism)).
		Str(string(w.Salt)).
		Str(string(pub))
}

// WrapPrivateKey encrypts priv with a key derived from password.
func WrapPrivateKey(priv *ecdh.PrivateKey, password []byte, userID string, p vault.KDFParams) (*WrappedPrivateKey, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	salt, err := vault.RandomBytes(vault.SaltSize)
	if err != nil {
		return nil, err
	}
	w := &WrappedPrivateKey{Version: FormatVersion, Memory: p.Memory, Iterations: p.Iterations, Parallelism: p.Parallelism, Salt: salt}
	k := vault.DeriveKey(password, salt, p)
	defer vault.Wipe(k)
	raw := priv.Bytes()
	defer vault.Wipe(raw)
	w.Nonce, w.Ciphertext, err = vault.Encrypt(k, raw, accountKeyAAD(userID, w, priv.PublicKey().Bytes()))
	if err != nil {
		return nil, err
	}
	return w, nil
}

// UnwrapPrivateKey decrypts a wrapped private key and checks that it
// matches the expected public key. Stored KDF parameters are bounds-checked
// first, so a tampered record cannot force extreme resource use.
func UnwrapPrivateKey(w *WrappedPrivateKey, password []byte, userID string, pub []byte) (*ecdh.PrivateKey, error) {
	if w == nil || w.Version != FormatVersion {
		return nil, errors.New("unsupported account key format")
	}
	p := w.Params()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(w.Salt) < vault.SaltSize || len(w.Salt) > 64 {
		return nil, errors.New("account key salt has an unsupported length")
	}
	k := vault.DeriveKey(password, w.Salt, p)
	defer vault.Wipe(k)
	raw, err := vault.Decrypt(k, w.Nonce, w.Ciphertext, accountKeyAAD(userID, w, pub))
	if err != nil {
		return nil, ErrIncorrectPassword
	}
	defer vault.Wipe(raw)
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, ErrDecrypt
	}
	if subtle.ConstantTimeCompare(priv.PublicKey().Bytes(), pub) != 1 {
		return nil, ErrDecrypt
	}
	return priv, nil
}

// Secret is the random part of an invite code or service token. Two keys are
// derived from it: an X25519 private key (environment keys are sealed to its
// public key) and an auth key, whose SHA-256 the server stores to check that
// a request comes from someone holding the secret. The secret itself is
// never sent to the server.
type Secret []byte

// NewSecret returns a random secret.
func NewSecret() (Secret, error) { return vault.RandomBytes(SecretSize) }

// PrivateKey derives the secret's X25519 key.
func (s Secret) PrivateKey() (*ecdh.PrivateKey, error) {
	b, err := hkdf.Key(sha256.New, s, nil, "ven/principal-key/v1", KeySize)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(b)
	return ecdh.X25519().NewPrivateKey(b)
}

// AuthKey derives the value sent to the server to prove possession.
func (s Secret) AuthKey() ([]byte, error) {
	return hkdf.Key(sha256.New, s, nil, "ven/principal-auth/v1", 32)
}

// AuthHash is what the server stores for an auth key.
func AuthHash(authKey []byte) []byte {
	h := sha256.Sum256(authKey)
	return h[:]
}

// CheckAuth compares an auth key against a stored hash in constant time.
func CheckAuth(authKey, storedHash []byte) bool {
	return len(storedHash) == sha256.Size && subtle.ConstantTimeCompare(AuthHash(authKey), storedHash) == 1
}

// Credential prefixes.
const (
	InvitePrefix = "ven_inv_"
	TokenPrefix  = "ven_st_"
)

var b64 = base64.RawURLEncoding

// FormatCredential renders prefix + id + "_" + secret.
func FormatCredential(prefix, id string, s Secret) string {
	return prefix + id + "_" + b64.EncodeToString(s)
}

// ParseCredential splits a credential produced by FormatCredential.
func ParseCredential(prefix, cred string) (id string, s Secret, err error) {
	cred = strings.TrimSpace(cred)
	rest, ok := strings.CutPrefix(cred, prefix)
	if !ok {
		return "", nil, fmt.Errorf("not a VEN credential (expected it to start with %s)", prefix)
	}
	id, enc, ok := strings.Cut(rest, "_")
	if !ok || !ValidID(id) {
		return "", nil, errors.New("malformed credential")
	}
	raw, err := b64.DecodeString(enc)
	if err != nil || len(raw) != SecretSize {
		return "", nil, errors.New("malformed credential")
	}
	return id, raw, nil
}

// NewID returns a random 128-bit hex identifier.
func NewID() (string, error) {
	b, err := vault.RandomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ValidID reports whether id looks like a NewID result.
func ValidID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && strings.ToLower(id) == id
}
