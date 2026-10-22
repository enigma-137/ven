// Package vault implements vault initialization, unlocking, password changes
// and the in-memory data key used to encrypt variable values.
package vault

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"unicode/utf8"

	"github.com/enigma-137/ven/internal/storage"
	"golang.org/x/crypto/argon2"
)

var (
	// ErrNotInitialized means no vault has been created yet.
	ErrNotInitialized = errors.New("vault is not initialized; run `ven init` first")
	// ErrAlreadyInitialized means init was attempted on an existing vault.
	ErrAlreadyInitialized = errors.New("vault is already initialized")
	// ErrIncorrectPassword means unlock failed authentication.
	ErrIncorrectPassword = errors.New("incorrect master password")
	// ErrLocked means an operation needs an unlocked vault key.
	ErrLocked = errors.New("vault is locked")
)

const (
	// MinPasswordLength is the minimum master password length in characters.
	MinPasswordLength = 10
	// MaxPasswordBytes caps password input size.
	MaxPasswordBytes = 1024
)

// ValidatePassword checks master password policy.
func ValidatePassword(pw []byte) error {
	if !utf8.Valid(pw) {
		return errors.New("master password must be valid UTF-8")
	}
	if len(pw) > MaxPasswordBytes {
		return fmt.Errorf("master password must be at most %d bytes", MaxPasswordBytes)
	}
	if utf8.RuneCount(pw) < MinPasswordLength {
		return fmt.Errorf("master password must be at least %d characters", MinPasswordLength)
	}
	return nil
}

// Key is an unlocked vault data key. Destroy it when no longer needed.
type Key struct {
	mu      sync.RWMutex
	key     []byte
	vaultID string
}

// VaultID returns the vault identifier bound into associated data.
func (k *Key) VaultID() string { return k.vaultID }

// Seal encrypts plaintext with associated data.
func (k *Key) Seal(plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.key == nil {
		return nil, nil, ErrLocked
	}
	return seal(k.key, plaintext, aad)
}

// Open decrypts ciphertext with associated data.
func (k *Key) Open(nonce, ciphertext, aad []byte) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.key == nil {
		return nil, ErrLocked
	}
	return open(k.key, nonce, ciphertext, aad)
}

// Destroy wipes the key material. Later Seal/Open calls return ErrLocked.
func (k *Key) Destroy() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	Wipe(k.key)
	k.key = nil
}

// Status describes the vault without needing the password.
type Status struct {
	Initialized bool
	VaultID     string
	KDF         KDFParams
	CreatedAt   string
	UpdatedAt   string
}

// Service manages the vault lifecycle.
type Service struct {
	db  *storage.DB
	kdf KDFParams
}

// Option configures a Service.
type Option func(*Service)

// WithKDFParams overrides the Argon2id parameters used for new wraps.
// Intended for tests; parameters must still pass Validate.
func WithKDFParams(p KDFParams) Option { return func(s *Service) { s.kdf = p } }

// NewService returns a vault service backed by db.
func NewService(db *storage.DB, opts ...Option) *Service {
	s := &Service{db: db, kdf: DefaultKDF}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Status reports whether the vault exists and its public metadata.
func (s *Service) Status(ctx context.Context) (Status, error) {
	c, err := storage.GetVaultConfig(ctx, s.db)
	if errors.Is(err, storage.ErrNotFound) {
		return Status{}, nil
	}
	if err != nil {
		return Status{}, err
	}
	return Status{
		Initialized: true,
		VaultID:     c.VaultID,
		KDF:         KDFParams{Memory: c.KDFMemoryKiB, Iterations: c.KDFIterations, Parallelism: c.KDFParallelism},
		CreatedAt:   storage.FormatTime(c.CreatedAt),
		UpdatedAt:   storage.FormatTime(c.UpdatedAt),
	}, nil
}

// Init creates the vault: a random data key wrapped with a key derived from
// password. It returns the unlocked key.
func (s *Service) Init(ctx context.Context, password []byte) (*Key, error) {
	if err := ValidatePassword(password); err != nil {
		return nil, err
	}
	if err := s.kdf.Validate(); err != nil {
		return nil, err
	}
	dataKey, err := randomBytes(KeySize)
	if err != nil {
		return nil, err
	}
	now := storage.Now()
	cfg := &storage.VaultConfig{
		VaultID:       storage.NewID(),
		FormatVersion: FormatVersion,
		KDFAlgorithm:  "argon2id",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := s.wrap(cfg, dataKey, password); err != nil {
		Wipe(dataKey)
		return nil, err
	}
	err = s.db.WithTx(ctx, func(tx *sql.Tx) error {
		return storage.InsertVaultConfig(ctx, tx, cfg)
	})
	if errors.Is(err, storage.ErrConflict) {
		Wipe(dataKey)
		return nil, ErrAlreadyInitialized
	}
	if err != nil {
		Wipe(dataKey)
		return nil, err
	}
	return &Key{key: dataKey, vaultID: cfg.VaultID}, nil
}

// wrap derives a wrapping key with fresh salt and encrypts dataKey into cfg.
func (s *Service) wrap(cfg *storage.VaultConfig, dataKey, password []byte) error {
	salt, err := randomBytes(SaltSize)
	if err != nil {
		return err
	}
	cfg.KDFVersion = argon2.Version
	cfg.KDFMemoryKiB, cfg.KDFIterations, cfg.KDFParallelism = s.kdf.Memory, s.kdf.Iterations, s.kdf.Parallelism
	cfg.KDFSalt = salt
	wk := deriveWrappingKey(password, salt, s.kdf)
	defer Wipe(wk)
	nonce, ct, err := seal(wk, dataKey, wrappedKeyAAD(cfg.VaultID, cfg.FormatVersion, cfg.KDFVersion, s.kdf, salt))
	if err != nil {
		return err
	}
	cfg.WrappedKeyNonce, cfg.WrappedKey = nonce, ct
	return nil
}

func unwrap(cfg *storage.VaultConfig, password []byte) ([]byte, error) {
	if cfg.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("unsupported vault format version %d", cfg.FormatVersion)
	}
	if cfg.KDFAlgorithm != "argon2id" || cfg.KDFVersion != argon2.Version {
		return nil, fmt.Errorf("unsupported key derivation %s v%d", cfg.KDFAlgorithm, cfg.KDFVersion)
	}
	p := KDFParams{Memory: cfg.KDFMemoryKiB, Iterations: cfg.KDFIterations, Parallelism: cfg.KDFParallelism}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("vault metadata rejected: %w", err)
	}
	if len(cfg.KDFSalt) < SaltSize || len(cfg.KDFSalt) > 64 {
		return nil, errors.New("vault metadata rejected: invalid salt length")
	}
	wk := deriveWrappingKey(password, cfg.KDFSalt, p)
	defer Wipe(wk)
	dataKey, err := open(wk, cfg.WrappedKeyNonce, cfg.WrappedKey, wrappedKeyAAD(cfg.VaultID, cfg.FormatVersion, cfg.KDFVersion, p, cfg.KDFSalt))
	if err != nil {
		return nil, ErrIncorrectPassword
	}
	if len(dataKey) != KeySize {
		Wipe(dataKey)
		return nil, errors.New("vault metadata rejected: invalid key length")
	}
	return dataKey, nil
}

// Unlock verifies password and returns the data key.
func (s *Service) Unlock(ctx context.Context, password []byte) (*Key, error) {
	cfg, err := storage.GetVaultConfig(ctx, s.db)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, err
	}
	dataKey, err := unwrap(cfg, password)
	if err != nil {
		return nil, err
	}
	return &Key{key: dataKey, vaultID: cfg.VaultID}, nil
}

// ChangePassword rewraps the existing data key under a new password. Stored
// values are untouched because the data key itself does not change.
func (s *Service) ChangePassword(ctx context.Context, current, next []byte) error {
	if err := ValidatePassword(next); err != nil {
		return err
	}
	if err := s.kdf.Validate(); err != nil {
		return err
	}
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		cfg, err := storage.GetVaultConfig(ctx, tx)
		if errors.Is(err, storage.ErrNotFound) {
			return ErrNotInitialized
		}
		if err != nil {
			return err
		}
		dataKey, err := unwrap(cfg, current)
		if err != nil {
			return err
		}
		defer Wipe(dataKey)
		if err := s.wrap(cfg, dataKey, next); err != nil {
			return err
		}
		cfg.UpdatedAt = storage.Now()
		return storage.UpdateVaultKey(ctx, tx, cfg)
	})
}
