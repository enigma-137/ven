// Package environments manages environments within projects.
package environments

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/enigma-137/ven/internal/domain"
	"github.com/enigma-137/ven/internal/projects"
	"github.com/enigma-137/ven/internal/storage"
)

// Environment is an environment with its variable count.
type Environment = storage.Environment

// Service manages environments.
type Service struct {
	db       *storage.DB
	projects *projects.Service
}

// NewService returns an environment service.
func NewService(db *storage.DB, p *projects.Service) *Service {
	return &Service{db: db, projects: p}
}

// List returns a project's environments.
func (s *Service) List(ctx context.Context, projectRef string) (projects.Project, []Environment, error) {
	p, err := s.projects.Resolve(ctx, projectRef)
	if err != nil {
		return p, nil, err
	}
	envs, err := storage.ListEnvironments(ctx, s.db, p.ID)
	return p, envs, err
}

// Resolve finds an environment by slug or name within a project.
func (s *Service) Resolve(ctx context.Context, projectRef, envRef string) (projects.Project, Environment, error) {
	p, err := s.projects.Resolve(ctx, projectRef)
	if err != nil {
		return p, Environment{}, err
	}
	e, err := ResolveIn(ctx, s.db, p.ID, envRef)
	return p, e, err
}

// ResolveIn finds an environment by slug or name using an explicit querier.
func ResolveIn(ctx context.Context, q storage.Querier, projectID, ref string) (Environment, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Environment{}, domain.Invalid("environment", "is required")
	}
	for _, slug := range []string{ref, domain.Slugify(ref)} {
		e, err := storage.GetEnvironmentBySlug(ctx, q, projectID, slug)
		if err == nil || !errors.Is(err, storage.ErrNotFound) {
			return e, err
		}
	}
	envs, err := storage.ListEnvironments(ctx, q, projectID)
	if err != nil {
		return Environment{}, err
	}
	for _, e := range envs {
		if strings.EqualFold(e.Name, ref) {
			return e, nil
		}
	}
	return Environment{}, fmt.Errorf("environment %q: %w", ref, storage.ErrNotFound)
}

// Get returns an environment by ID.
func (s *Service) Get(ctx context.Context, id string) (Environment, error) {
	return storage.GetEnvironmentByID(ctx, s.db, id)
}

// Create adds an environment to a project.
func (s *Service) Create(ctx context.Context, projectRef, name string) (Environment, error) {
	name, err := domain.CleanName("name", name, 64)
	if err != nil {
		return Environment{}, err
	}
	var out Environment
	err = s.db.WithTx(ctx, func(tx *sql.Tx) error {
		p, err := projects.ResolveIn(ctx, tx, projectRef)
		if err != nil {
			return err
		}
		order, err := storage.NextEnvironmentOrder(ctx, tx, p.ID)
		if err != nil {
			return err
		}
		now := storage.Now()
		e := Environment{ID: storage.NewID(), ProjectID: p.ID, Name: name, Slug: domain.Slugify(name),
			SortOrder: order, CreatedAt: now, UpdatedAt: now}
		if err := storage.InsertEnvironment(ctx, tx, &e); err != nil {
			if errors.Is(err, storage.ErrConflict) {
				return fmt.Errorf("environment %q already exists in %s: %w", e.Slug, p.Slug, storage.ErrConflict)
			}
			return err
		}
		if err := storage.TouchProject(ctx, tx, p.ID, now); err != nil {
			return err
		}
		out = e
		return nil
	})
	return out, err
}

// Rename renames an environment (and its slug).
func (s *Service) Rename(ctx context.Context, projectRef, envRef, name string) (Environment, error) {
	name, err := domain.CleanName("name", name, 64)
	if err != nil {
		return Environment{}, err
	}
	var out Environment
	err = s.db.WithTx(ctx, func(tx *sql.Tx) error {
		p, err := projects.ResolveIn(ctx, tx, projectRef)
		if err != nil {
			return err
		}
		e, err := ResolveIn(ctx, tx, p.ID, envRef)
		if err != nil {
			return err
		}
		e.Name, e.Slug, e.UpdatedAt = name, domain.Slugify(name), storage.Now()
		if err := storage.UpdateEnvironment(ctx, tx, &e); err != nil {
			if errors.Is(err, storage.ErrConflict) {
				return fmt.Errorf("environment %q already exists in %s: %w", e.Slug, p.Slug, storage.ErrConflict)
			}
			return err
		}
		out = e
		return storage.TouchProject(ctx, tx, p.ID, e.UpdatedAt)
	})
	return out, err
}

// Delete removes an environment and its variables. Interactive callers must
// confirm before calling.
func (s *Service) Delete(ctx context.Context, projectRef, envRef string) (Environment, error) {
	var out Environment
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		p, err := projects.ResolveIn(ctx, tx, projectRef)
		if err != nil {
			return err
		}
		e, err := ResolveIn(ctx, tx, p.ID, envRef)
		if err != nil {
			return err
		}
		out = e
		if err := storage.DeleteEnvironment(ctx, tx, e.ID); err != nil {
			return err
		}
		return storage.TouchProject(ctx, tx, p.ID, storage.Now())
	})
	return out, err
}
