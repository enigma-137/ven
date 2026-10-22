package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// KeySize is the AES-256 key length in bytes.
	KeySize = 32
	// NonceSize is the AES-GCM standard nonce length in bytes.
	NonceSize = 12
	// SaltSize is the Argon2id salt length in bytes.
	SaltSize = 16

	// FormatVersion identifies the vault key-wrapping format.
	FormatVersion = 1
	// ValueFormatV1 identifies the variable value encryption format.
	ValueFormatV1 = 1
)

// ErrDecrypt is returned when authenticated decryption fails (wrong key,
// tampered ciphertext or mismatched associated data).
var ErrDecrypt = errors.New("decryption failed: data is corrupted or does not belong to this record")

// KDFParams are Argon2id parameters. Memory is in KiB.
type KDFParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
}

// DefaultKDF follows the RFC 9106 second recommended option
// (m=64 MiB, t=3, p=4).
var DefaultKDF = KDFParams{Memory: 64 * 1024, Iterations: 3, Parallelism: 4}

// Bounds accepted when reading parameters from disk. They stop a tampered
// vault_config from forcing absurd memory/CPU use or trivially weak settings.
const (
	minMemoryKiB   = 8 * 1024
	maxMemoryKiB   = 1024 * 1024
	minIterations  = 1
	maxIterations  = 10
	minParallelism = 1
	maxParallelism = 16
)

// Validate checks that p is within the supported bounds.
func (p KDFParams) Validate() error {
	if p.Memory < minMemoryKiB || p.Memory > maxMemoryKiB {
		return fmt.Errorf("argon2id memory %d KiB outside supported range %d-%d", p.Memory, minMemoryKiB, maxMemoryKiB)
	}
	if p.Iterations < minIterations || p.Iterations > maxIterations {
		return fmt.Errorf("argon2id iterations %d outside supported range %d-%d", p.Iterations, minIterations, maxIterations)
	}
	if p.Parallelism < minParallelism || p.Parallelism > maxParallelism {
		return fmt.Errorf("argon2id parallelism %d outside supported range %d-%d", p.Parallelism, minParallelism, maxParallelism)
	}
	return nil
}

func deriveWrappingKey(password, salt []byte, p KDFParams) []byte {
	return argon2.IDKey(password, salt, p.Iterations, p.Memory, p.Parallelism, KeySize)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return b, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal encrypts plaintext with a fresh random nonce. With random 96-bit
// nonces the collision probability stays negligible for far more values than
// a local vault will ever hold.
func seal(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = randomBytes(NonceSize)
	if err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

func open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, ErrDecrypt
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// aadBuilder produces unambiguous associated data: a fixed context label
// followed by length-prefixed fields.
type aadBuilder []byte

func newAAD(label string) aadBuilder {
	return aadBuilder(label).str("")
}

func (a aadBuilder) str(s string) aadBuilder {
	a = binary.BigEndian.AppendUint32(a, uint32(len(s)))
	return append(a, s...)
}

func (a aadBuilder) u32(v uint32) aadBuilder {
	return binary.BigEndian.AppendUint32(a, v)
}

// wrappedKeyAAD binds the wrapped vault key to the vault ID, format version
// and KDF parameters, so tampering with stored metadata fails authentication.
func wrappedKeyAAD(vaultID string, formatVersion, kdfVersion int, p KDFParams, salt []byte) []byte {
	return newAAD("ven/vault-key").
		u32(uint32(formatVersion)).
		str(vaultID).
		str("argon2id").
		u32(uint32(kdfVersion)).
		u32(p.Memory).
		u32(p.Iterations).
		u32(uint32(p.Parallelism)).
		str(string(salt))
}

// ValueAAD binds an encrypted variable value to its vault, project,
// environment and variable record.
func ValueAAD(encVersion int, vaultID, projectID, environmentID, variableID string) []byte {
	return newAAD("ven/variable-value").
		u32(uint32(encVersion)).
		str(vaultID).
		str(projectID).
		str(environmentID).
		str(variableID)
}

// Wipe overwrites b with zeros. Best effort: the Go runtime may already have
// copied the data elsewhere.
func Wipe(b []byte) {
	clear(b)
}
