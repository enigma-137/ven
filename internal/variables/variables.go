// Package variables manages encrypted environment variables, including
// import planning/commit and dotenv export.
package variables

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/enigma-137/ven/internal/domain"
	"github.com/enigma-137/ven/internal/envfile"
	"github.com/enigma-137/ven/internal/storage"
	"github.com/enigma-137/ven/internal/vault"
)

// Variable is variable metadata. It never carries the value.
type Variable struct {
	ID            string    `json:"id"`
	EnvironmentID string    `json:"environmentId"`
	Key           string    `json:"key"`
	Type          string    `json:"type"`
	Description   string    `json:"description"`
	SortOrder     int       `json:"sortOrder"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

func fromRow(r storage.Variable) Variable {
	return Variable{ID: r.ID, EnvironmentID: r.EnvironmentID, Key: r.Key, Type: r.DisplayType,
		Description: r.Description, SortOrder: r.SortOrder, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

// Service manages variables.
type Service struct{ db *storage.DB }

// NewService returns a variable service.
func NewService(db *storage.DB) *Service { return &Service{db: db} }

// ValidateKey checks a variable key.
func ValidateKey(key string) error {
	if key == "" {
		return domain.Invalid("key", "is required")
	}
	if !envfile.ValidKey(key) {
		return domain.Invalid("key", "%s (max %d characters)", envfile.KeyRule, envfile.MaxKeyLength)
	}
	return nil
}

// ValidateValue checks a variable value without echoing it.
func ValidateValue(v string) error {
	if !utf8.ValidString(v) {
		return domain.Invalid("value", "must be valid UTF-8")
	}
	if strings.ContainsRune(v, 0) {
		return domain.Invalid("value", "must not contain NUL bytes")
	}
	if len(v) > envfile.MaxValueSize {
		return domain.Invalid("value", "must be at most %d bytes", envfile.MaxValueSize)
	}
	return nil
}

func encrypt(k *vault.Key, projectID string, r *storage.Variable, value string) error {
	pt := []byte(value)
	defer vault.Wipe(pt)
	aad := vault.ValueAAD(vault.ValueFormatV1, k.VaultID(), projectID, r.EnvironmentID, r.ID)
	nonce, ct, err := k.Seal(pt, aad)
	if err != nil {
		return err
	}
	r.Nonce, r.Ciphertext, r.EncVersion = nonce, ct, vault.ValueFormatV1
	return nil
}

func decrypt(k *vault.Key, projectID string, r storage.Variable) (string, error) {
	if r.EncVersion != vault.ValueFormatV1 {
		return "", fmt.Errorf("variable %s: unsupported encryption version %d", r.Key, r.EncVersion)
	}
	aad := vault.ValueAAD(r.EncVersion, k.VaultID(), projectID, r.EnvironmentID, r.ID)
	pt, err := k.Open(r.Nonce, r.Ciphertext, aad)
	if err != nil {
		if errors.Is(err, vault.ErrDecrypt) {
			return "", fmt.Errorf("variable %s: %w", r.Key, err)
		}
		return "", err
	}
	s := string(pt)
	vault.Wipe(pt)
	return s, nil
}

func projectOf(ctx context.Context, q storage.Querier, envID string) (storage.Environment, error) {
	e, err := storage.GetEnvironmentByID(ctx, q, envID)
	if err != nil {
		return e, fmt.Errorf("environment: %w", err)
	}
	return e, nil
}

// List returns metadata for an environment's variables. It needs no key.
func (s *Service) List(ctx context.Context, envID, search string) ([]Variable, error) {
	rows, err := storage.ListVariables(ctx, s.db, envID, search)
	if err != nil {
		return nil, err
	}
	out := make([]Variable, 0, len(rows))
	for _, r := range rows {
		out = append(out, fromRow(r))
	}
	return out, nil
}

// Meta returns one variable's metadata by ID.
func (s *Service) Meta(ctx context.Context, id string) (Variable, error) {
	r, err := storage.GetVariableByID(ctx, s.db, id)
	return fromRow(r), err
}

// Get returns a variable and its decrypted value by key.
func (s *Service) Get(ctx context.Context, k *vault.Key, envID, key string) (Variable, string, error) {
	e, err := projectOf(ctx, s.db, envID)
	if err != nil {
		return Variable{}, "", err
	}
	r, err := storage.GetVariableByKey(ctx, s.db, envID, key)
	if err != nil {
		return Variable{}, "", fmt.Errorf("variable %s: %w", key, err)
	}
	v, err := decrypt(k, e.ProjectID, r)
	return fromRow(r), v, err
}

// GetByID returns a variable and its decrypted value by ID.
func (s *Service) GetByID(ctx context.Context, k *vault.Key, id string) (Variable, string, error) {
	r, err := storage.GetVariableByID(ctx, s.db, id)
	if err != nil {
		return Variable{}, "", err
	}
	e, err := projectOf(ctx, s.db, r.EnvironmentID)
	if err != nil {
		return Variable{}, "", err
	}
	v, err := decrypt(k, e.ProjectID, r)
	return fromRow(r), v, err
}

// TextValues decrypts the values of text-typed variables only, keyed by ID.
func (s *Service) TextValues(ctx context.Context, k *vault.Key, envID string) (map[string]string, error) {
	e, err := projectOf(ctx, s.db, envID)
	if err != nil {
		return nil, err
	}
	rows, err := storage.ListVariables(ctx, s.db, envID, "")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range rows {
		if r.DisplayType != TypeText {
			continue
		}
		v, err := decrypt(k, e.ProjectID, r)
		if err != nil {
			return nil, err
		}
		out[r.ID] = v
	}
	return out, nil
}

// SetInput creates or updates a variable by key.
type SetInput struct {
	Key         string
	Value       string
	Type        string  // "" keeps the existing type or classifies a new key
	Description *string // nil keeps the existing description
	// CreateOnly fails with storage.ErrConflict if the key already exists.
	CreateOnly bool
}

// Set creates or replaces the value of the variable with the given key.
func (s *Service) Set(ctx context.Context, k *vault.Key, envID string, in SetInput) (Variable, bool, error) {
	if err := ValidateKey(in.Key); err != nil {
		return Variable{}, false, err
	}
	if err := ValidateValue(in.Value); err != nil {
		return Variable{}, false, err
	}
	if in.Type != "" && !ValidType(in.Type) {
		return Variable{}, false, domain.Invalid("type", "must be %q or %q", TypeSecret, TypeText)
	}
	var desc string
	if in.Description != nil {
		d, err := domain.CleanDescription(*in.Description)
		if err != nil {
			return Variable{}, false, err
		}
		desc = d
	}
	var out storage.Variable
	created := false
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		e, err := projectOf(ctx, tx, envID)
		if err != nil {
			return err
		}
		now := storage.Now()
		r, err := storage.GetVariableByKey(ctx, tx, envID, in.Key)
		switch {
		case errors.Is(err, storage.ErrNotFound):
			created = true
			order, err := storage.NextVariableOrder(ctx, tx, envID)
			if err != nil {
				return err
			}
			typ := in.Type
			if typ == "" {
				typ, _ = Classify(in.Key)
			}
			r = storage.Variable{ID: storage.NewID(), EnvironmentID: envID, Key: in.Key, DisplayType: typ,
				Description: desc, SortOrder: order, CreatedAt: now, UpdatedAt: now}
			if err := encrypt(k, e.ProjectID, &r, in.Value); err != nil {
				return err
			}
			if err := storage.InsertVariable(ctx, tx, &r); err != nil {
				return err
			}
		case err != nil:
			return err
		case in.CreateOnly:
			return fmt.Errorf("variable %s already exists in this environment: %w", in.Key, storage.ErrConflict)
		default:
			if in.Type != "" {
				r.DisplayType = in.Type
			}
			if in.Description != nil {
				r.Description = desc
			}
			r.UpdatedAt = now
			if err := encrypt(k, e.ProjectID, &r, in.Value); err != nil {
				return err
			}
			if err := storage.UpdateVariable(ctx, tx, &r); err != nil {
				return err
			}
		}
		out = r
		return storage.TouchEnvironment(ctx, tx, envID, now)
	})
	return fromRow(out), created, err
}

// UpdateInput holds optional changes to an existing variable.
type UpdateInput struct {
	Key         *string
	Value       *string
	Type        *string
	Description *string
}

// Update modifies a variable by ID. A key change keeps the ciphertext valid
// because associated data binds the record ID, not the key name.
func (s *Service) Update(ctx context.Context, k *vault.Key, id string, in UpdateInput) (Variable, error) {
	if in.Key != nil {
		if err := ValidateKey(*in.Key); err != nil {
			return Variable{}, err
		}
	}
	if in.Value != nil {
		if err := ValidateValue(*in.Value); err != nil {
			return Variable{}, err
		}
	}
	if in.Type != nil && !ValidType(*in.Type) {
		return Variable{}, domain.Invalid("type", "must be %q or %q", TypeSecret, TypeText)
	}
	var out storage.Variable
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		r, err := storage.GetVariableByID(ctx, tx, id)
		if err != nil {
			return err
		}
		e, err := projectOf(ctx, tx, r.EnvironmentID)
		if err != nil {
			return err
		}
		if in.Key != nil {
			r.Key = *in.Key
		}
		if in.Type != nil {
			r.DisplayType = *in.Type
		}
		if in.Description != nil {
			d, err := domain.CleanDescription(*in.Description)
			if err != nil {
				return err
			}
			r.Description = d
		}
		if in.Value != nil {
			if err := encrypt(k, e.ProjectID, &r, *in.Value); err != nil {
				return err
			}
		} else if _, err := decrypt(k, e.ProjectID, r); err != nil {
			// Even metadata-only edits require the vault to be unlocked
			// and the record to authenticate.
			return err
		}
		r.UpdatedAt = storage.Now()
		if err := storage.UpdateVariable(ctx, tx, &r); err != nil {
			if errors.Is(err, storage.ErrConflict) {
				return fmt.Errorf("variable %s already exists in this environment: %w", r.Key, storage.ErrConflict)
			}
			return err
		}
		out = r
		return storage.TouchEnvironment(ctx, tx, r.EnvironmentID, r.UpdatedAt)
	})
	return fromRow(out), err
}

// Delete removes a variable by key.
func (s *Service) Delete(ctx context.Context, envID, key string) (Variable, error) {
	var out storage.Variable
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		r, err := storage.GetVariableByKey(ctx, tx, envID, key)
		if err != nil {
			return fmt.Errorf("variable %s: %w", key, err)
		}
		out = r
		if err := storage.DeleteVariable(ctx, tx, r.ID); err != nil {
			return err
		}
		return storage.TouchEnvironment(ctx, tx, envID, storage.Now())
	})
	return fromRow(out), err
}

// DeleteByID removes a variable by ID.
func (s *Service) DeleteByID(ctx context.Context, id string) (Variable, error) {
	var out storage.Variable
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		r, err := storage.GetVariableByID(ctx, tx, id)
		if err != nil {
			return err
		}
		out = r
		if err := storage.DeleteVariable(ctx, tx, r.ID); err != nil {
			return err
		}
		return storage.TouchEnvironment(ctx, tx, r.EnvironmentID, storage.Now())
	})
	return fromRow(out), err
}

// Entries decrypts every variable of an environment in display order.
func (s *Service) Entries(ctx context.Context, k *vault.Key, envID string) ([]envfile.Entry, error) {
	e, err := projectOf(ctx, s.db, envID)
	if err != nil {
		return nil, err
	}
	rows, err := storage.ListVariables(ctx, s.db, envID, "")
	if err != nil {
		return nil, err
	}
	out := make([]envfile.Entry, 0, len(rows))
	for _, r := range rows {
		v, err := decrypt(k, e.ProjectID, r)
		if err != nil {
			return nil, err
		}
		out = append(out, envfile.Entry{Key: r.Key, Value: v})
	}
	return out, nil
}

// Export renders an environment as dotenv content.
func (s *Service) Export(ctx context.Context, k *vault.Key, envID string) ([]byte, int, error) {
	entries, err := s.Entries(ctx, k, envID)
	if err != nil {
		return nil, 0, err
	}
	return envfile.Serialize(entries), len(entries), nil
}
