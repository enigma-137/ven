// Package projects manages VEN projects.
package projects

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/enigma-137/ven/internal/domain"
	"github.com/enigma-137/ven/internal/storage"
)

// Project is a project with its environment count.
type Project = storage.Project

// DefaultEnvironments are offered during project setup.
var DefaultEnvironments = []string{"development", "staging", "production"}

// Service manages projects.
type Service struct{ db *storage.DB }

// NewService returns a project service.
func NewService(db *storage.DB) *Service { return &Service{db: db} }

// List returns projects, optionally filtered by a case-insensitive search
// over name, slug and description.
func (s *Service) List(ctx context.Context, search string) ([]Project, error) {
	all, err := storage.ListProjects(ctx, s.db)
	if err != nil {
		return nil, err
	}
	search = strings.ToLower(strings.TrimSpace(search))
	if search == "" {
		return all, nil
	}
	var out []Project
	for _, p := range all {
		if strings.Contains(strings.ToLower(p.Name), search) || strings.Contains(p.Slug, search) ||
			strings.Contains(strings.ToLower(p.Description), search) {
			out = append(out, p)
		}
	}
	return out, nil
}

// Resolve finds a project by slug or (unambiguous, case-insensitive) name.
func (s *Service) Resolve(ctx context.Context, ref string) (Project, error) {
	return ResolveIn(ctx, s.db, ref)
}

// ResolveIn is Resolve using an explicit querier (e.g. a transaction).
func ResolveIn(ctx context.Context, q storage.Querier, ref string) (Project, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Project{}, domain.Invalid("project", "is required")
	}
	if p, err := storage.GetProjectBySlug(ctx, q, ref); err == nil || !errors.Is(err, storage.ErrNotFound) {
		return p, err
	}
	if slug := domain.Slugify(ref); slug != ref {
		if p, err := storage.GetProjectBySlug(ctx, q, slug); err == nil || !errors.Is(err, storage.ErrNotFound) {
			return p, err
		}
	}
	matches, err := storage.FindProjectsByName(ctx, q, ref)
	if err != nil {
		return Project{}, err
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	return Project{}, fmt.Errorf("project %q: %w", ref, storage.ErrNotFound)
}

// CreateInput describes a new project.
type CreateInput struct {
	Name         string
	Description  string
	Environments []string // environment names to create in the same transaction
}

// Create creates a project and its initial environments atomically.
func (s *Service) Create(ctx context.Context, in CreateInput) (Project, []storage.Environment, error) {
	name, err := domain.CleanName("name", in.Name, 100)
	if err != nil {
		return Project{}, nil, err
	}
	desc, err := domain.CleanDescription(in.Description)
	if err != nil {
		return Project{}, nil, err
	}
	now := storage.Now()
	p := Project{ID: storage.NewID(), Name: name, Slug: domain.Slugify(name), Description: desc, CreatedAt: now, UpdatedAt: now}

	var envs []storage.Environment
	seen := map[string]bool{}
	for i, raw := range in.Environments {
		envName, err := domain.CleanName("environment", raw, 64)
		if err != nil {
			return Project{}, nil, err
		}
		slug := domain.Slugify(envName)
		if seen[slug] {
			return Project{}, nil, domain.Invalid("environment", "%q is listed more than once", envName)
		}
		seen[slug] = true
		envs = append(envs, storage.Environment{ID: storage.NewID(), ProjectID: p.ID, Name: envName, Slug: slug,
			SortOrder: i, CreatedAt: now, UpdatedAt: now})
	}

	err = s.db.WithTx(ctx, func(tx *sql.Tx) error {
		if err := storage.InsertProject(ctx, tx, &p); err != nil {
			if errors.Is(err, storage.ErrConflict) {
				return fmt.Errorf("a project with slug %q already exists: %w", p.Slug, storage.ErrConflict)
			}
			return err
		}
		for i := range envs {
			if err := storage.InsertEnvironment(ctx, tx, &envs[i]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Project{}, nil, err
	}
	p.EnvironmentCount = len(envs)
	return p, envs, nil
}

// UpdateInput holds optional changes. Renaming also updates the slug.
type UpdateInput struct {
	Name        *string
	Description *string
}

// Update renames a project and/or changes its description.
func (s *Service) Update(ctx context.Context, ref string, in UpdateInput) (Project, error) {
	var out Project
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		p, err := ResolveIn(ctx, tx, ref)
		if err != nil {
			return err
		}
		if in.Name != nil {
			name, err := domain.CleanName("name", *in.Name, 100)
			if err != nil {
				return err
			}
			p.Name, p.Slug = name, domain.Slugify(name)
		}
		if in.Description != nil {
			desc, err := domain.CleanDescription(*in.Description)
			if err != nil {
				return err
			}
			p.Description = desc
		}
		p.UpdatedAt = storage.Now()
		if err := storage.UpdateProject(ctx, tx, &p); err != nil {
			if errors.Is(err, storage.ErrConflict) {
				return fmt.Errorf("a project with slug %q already exists: %w", p.Slug, storage.ErrConflict)
			}
			return err
		}
		out = p
		return nil
	})
	return out, err
}

// Rename is shorthand for Update with a new name.
func (s *Service) Rename(ctx context.Context, ref, name string) (Project, error) {
	return s.Update(ctx, ref, UpdateInput{Name: &name})
}

// Delete removes a project with all its environments and variables.
// Interactive callers must confirm before calling.
func (s *Service) Delete(ctx context.Context, ref string) (Project, error) {
	var out Project
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		p, err := ResolveIn(ctx, tx, ref)
		if err != nil {
			return err
		}
		out = p
		return storage.DeleteProject(ctx, tx, p.ID)
	})
	return out, err
}
