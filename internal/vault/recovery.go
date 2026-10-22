package vault

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"errors"
	"strings"

	"github.com/enigma-137/ven/internal/storage"
)

// Recovery keys are 160 random bits shown once as base32 in groups of four,
// e.g. VENR-7K2Q-…. They are high-entropy, so HKDF (not Argon2id) turns
// them into a wrapping key.
const (
	recoverySecretSize = 20
	// VaultRecoveryPrefix marks local vault recovery keys.
	VaultRecoveryPrefix = "VENR"
)

var (
	// ErrIncorrectRecoveryKey means the recovery key did not unlock the vault.
	ErrIncorrectRecoveryKey = errors.New("incorrect recovery key")
	// ErrNoRecoveryKey means the vault has no recovery key set.
	ErrNoRecoveryKey = errors.New("this vault has no recovery key; create one with `ven password recovery-key`")

	recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// NewRecoveryKey returns a random secret and its printable form with the
// given prefix (for example VENR or VENA).
func NewRecoveryKey(prefix string) (secret []byte, printable string, err error) {
	secret, err = randomBytes(recoverySecretSize)
	if err != nil {
		return nil, "", err
	}
	enc := recoveryEncoding.EncodeToString(secret)
	groups := []string{prefix}
	for i := 0; i < len(enc); i += 4 {
		groups = append(groups, enc[i:i+4])
	}
	return secret, strings.Join(groups, "-"), nil
}

// ParseRecoveryKey accepts a printable recovery key with the expected
// prefix, tolerating lower case, spaces and missing dashes.
func ParseRecoveryKey(prefix, s string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "").Replace(strings.TrimSpace(s)))
	rest, ok := strings.CutPrefix(clean, prefix)
	if !ok {
		return nil, errors.New("not a recovery key (it should start with " + prefix + "-)")
	}
	secret, err := recoveryEncoding.DecodeString(rest)
	if err != nil || len(secret) != recoverySecretSize {
		return nil, errors.New("malformed recovery key: check for typos")
	}
	return secret, nil
}

// RecoveryWrappingKey derives a wrapping key from a recovery secret.
func RecoveryWrappingKey(secret, salt []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, salt, info, KeySize)
}

func recoveryAAD(vaultID string, salt []byte) []byte {
	return NewAAD("ven/vault-recovery").U32(FormatVersion).Str(vaultID).Str(string(salt))
}

const vaultRecoveryInfo = "ven/vault-recovery/v1"

// CreateRecoveryKey wraps the unlocked data key under a new recovery key,
// replacing any previous one, and returns the key to show the user once.
func (s *Service) CreateRecoveryKey(ctx context.Context, k *Key) (string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.key == nil {
		return "", ErrLocked
	}
	secret, printable, err := NewRecoveryKey(VaultRecoveryPrefix)
	if err != nil {
		return "", err
	}
	defer Wipe(secret)
	salt, err := randomBytes(SaltSize)
	if err != nil {
		return "", err
	}
	wk, err := RecoveryWrappingKey(secret, salt, vaultRecoveryInfo)
	if err != nil {
		return "", err
	}
	defer Wipe(wk)
	nonce, ct, err := seal(wk, k.key, recoveryAAD(k.vaultID, salt))
	if err != nil {
		return "", err
	}
	err = storage.PutVaultRecovery(ctx, s.db, &storage.VaultRecovery{Salt: salt, Nonce: nonce, WrappedKey: ct, CreatedAt: storage.Now()})
	if err != nil {
		return "", err
	}
	return printable, nil
}

// HasRecoveryKey reports whether a recovery key is set.
func (s *Service) HasRecoveryKey(ctx context.Context) (bool, error) {
	_, err := storage.GetVaultRecovery(ctx, s.db)
	if errors.Is(err, storage.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// ResetPassword unlocks the data key with the recovery key and wraps it
// under a new master password. Values are untouched and the recovery key
// stays valid.
func (s *Service) ResetPassword(ctx context.Context, recoveryKey string, next []byte) error {
	secret, err := ParseRecoveryKey(VaultRecoveryPrefix, recoveryKey)
	if err != nil {
		return err
	}
	defer Wipe(secret)
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
		rec, err := storage.GetVaultRecovery(ctx, tx)
		if errors.Is(err, storage.ErrNotFound) {
			return ErrNoRecoveryKey
		}
		if err != nil {
			return err
		}
		wk, err := RecoveryWrappingKey(secret, rec.Salt, vaultRecoveryInfo)
		if err != nil {
			return err
		}
		defer Wipe(wk)
		dataKey, err := open(wk, rec.Nonce, rec.WrappedKey, recoveryAAD(cfg.VaultID, rec.Salt))
		if err != nil {
			return ErrIncorrectRecoveryKey
		}
		defer Wipe(dataKey)
		if len(dataKey) != KeySize {
			return ErrIncorrectRecoveryKey
		}
		if err := s.wrap(cfg, dataKey, next); err != nil {
			return err
		}
		cfg.UpdatedAt = storage.Now()
		return storage.UpdateVaultKey(ctx, tx, cfg)
	})
}
