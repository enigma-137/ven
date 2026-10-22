package server

import (
	"context"
	"database/sql"
	"time"

	"github.com/enigma-137/ven/internal/remote/api"
	"github.com/enigma-137/ven/internal/storage"
)

type userRow struct {
	ID         string
	Provider   string
	Handle     string
	Name       string
	PublicKey  []byte
	WrappedKey string
}

func (u *userRow) api() api.User {
	return api.User{ID: u.ID, Provider: u.Provider, Handle: u.Handle, Name: u.Name, PublicKey: u.PublicKey}
}

const userSelect = `SELECT id, provider, handle, name, public_key, COALESCE(wrapped_private_key, '') FROM users`

func scanUser(sc interface{ Scan(...any) error }) (*userRow, error) {
	var u userRow
	if err := sc.Scan(&u.ID, &u.Provider, &u.Handle, &u.Name, &u.PublicKey, &u.WrappedKey); err != nil {
		return nil, storage.MapErr(err)
	}
	return &u, nil
}

func getUser(ctx context.Context, q storage.Querier, id string) (*userRow, error) {
	return scanUser(q.QueryRowContext(ctx, userSelect+` WHERE id = ?`, id))
}

func getUserByHandle(ctx context.Context, q storage.Querier, handle string) (*userRow, error) {
	return scanUser(q.QueryRowContext(ctx, userSelect+` WHERE handle = ?`, handle))
}

type projectRow struct {
	ID        string
	OwnerID   string
	Owner     string
	Name      string
	Slug      string
	CreatedAt time.Time
}

func getProject(ctx context.Context, q storage.Querier, owner, slug string) (*projectRow, error) {
	var p projectRow
	var created string
	err := q.QueryRowContext(ctx, `SELECT p.id, p.owner_id, u.handle, p.name, p.slug, p.created_at
		FROM projects p JOIN users u ON u.id = p.owner_id WHERE u.handle = ? AND p.slug = ?`, owner, slug).Scan(
		&p.ID, &p.OwnerID, &p.Owner, &p.Name, &p.Slug, &created)
	if err != nil {
		return nil, storage.MapErr(err)
	}
	p.CreatedAt = storage.ParseTime(created)
	return &p, nil
}

func getProjectByID(ctx context.Context, q storage.Querier, id string) (*projectRow, error) {
	var p projectRow
	var created string
	err := q.QueryRowContext(ctx, `SELECT p.id, p.owner_id, u.handle, p.name, p.slug, p.created_at
		FROM projects p JOIN users u ON u.id = p.owner_id WHERE p.id = ?`, id).Scan(
		&p.ID, &p.OwnerID, &p.Owner, &p.Name, &p.Slug, &created)
	if err != nil {
		return nil, storage.MapErr(err)
	}
	p.CreatedAt = storage.ParseTime(created)
	return &p, nil
}

type memberRow struct {
	Role      string
	ExpiresAt *time.Time
}

// getMember returns the membership, treating expired memberships as absent
// even before the sweep removes them.
func getMember(ctx context.Context, q storage.Querier, projectID, userID string, now time.Time) (*memberRow, error) {
	var m memberRow
	var exp sql.NullString
	err := q.QueryRowContext(ctx, `SELECT role, expires_at FROM members WHERE project_id = ? AND user_id = ?`, projectID, userID).Scan(&m.Role, &exp)
	if err != nil {
		return nil, storage.MapErr(err)
	}
	if exp.Valid {
		t := storage.ParseTime(exp.String)
		if !now.Before(t) {
			return nil, storage.ErrNotFound
		}
		m.ExpiresAt = &t
	}
	return &m, nil
}

type envRow struct {
	ID            string
	ProjectID     string
	Name          string
	Slug          string
	Protected     bool
	KeyVersion    int
	Revision      int
	Nonce         []byte
	Content       []byte
	NeedsRotation bool
	UpdatedAt     time.Time
}

func (e *envRow) api(access string) api.Environment {
	return api.Environment{ID: e.ID, Name: e.Name, Slug: e.Slug, Protected: e.Protected, KeyVersion: e.KeyVersion,
		Revision: e.Revision, NeedsRotation: e.NeedsRotation, Access: access, UpdatedAt: e.UpdatedAt}
}

const envSelect = `SELECT id, project_id, name, slug, protected, key_version, revision, content_nonce, content,
	needs_rotation, updated_at FROM environments`

func scanEnv(sc interface{ Scan(...any) error }) (*envRow, error) {
	var e envRow
	var updated string
	if err := sc.Scan(&e.ID, &e.ProjectID, &e.Name, &e.Slug, &e.Protected, &e.KeyVersion, &e.Revision,
		&e.Nonce, &e.Content, &e.NeedsRotation, &updated); err != nil {
		return nil, storage.MapErr(err)
	}
	e.UpdatedAt = storage.ParseTime(updated)
	return &e, nil
}

func getEnv(ctx context.Context, q storage.Querier, projectID, slug string) (*envRow, error) {
	return scanEnv(q.QueryRowContext(ctx, envSelect+` WHERE project_id = ? AND slug = ?`, projectID, slug))
}

func getEnvByID(ctx context.Context, q storage.Querier, id string) (*envRow, error) {
	return scanEnv(q.QueryRowContext(ctx, envSelect+` WHERE id = ?`, id))
}

func listEnvs(ctx context.Context, q storage.Querier, projectID string) ([]*envRow, error) {
	rows, err := q.QueryContext(ctx, envSelect+` WHERE project_id = ? ORDER BY created_at, slug`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*envRow
	for rows.Next() {
		e, err := scanEnv(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type grantRow struct {
	EnvironmentID string
	PrincipalType string
	PrincipalID   string
	KeyVersion    int
	SealedKey     []byte // nil while pending
}

func getGrant(ctx context.Context, q storage.Querier, envID, ptype, pid string) (*grantRow, error) {
	g := grantRow{EnvironmentID: envID, PrincipalType: ptype, PrincipalID: pid}
	err := q.QueryRowContext(ctx, `SELECT key_version, sealed_key FROM grants
		WHERE environment_id = ? AND principal_type = ? AND principal_id = ?`, envID, ptype, pid).Scan(&g.KeyVersion, &g.SealedKey)
	if err != nil {
		return nil, storage.MapErr(err)
	}
	return &g, nil
}

// grantsFor returns a principal's grants keyed by environment ID.
func grantsFor(ctx context.Context, q storage.Querier, ptype, pid string) (map[string]*grantRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT environment_id, key_version, sealed_key FROM grants
		WHERE principal_type = ? AND principal_id = ?`, ptype, pid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*grantRow{}
	for rows.Next() {
		g := grantRow{PrincipalType: ptype, PrincipalID: pid}
		if err := rows.Scan(&g.EnvironmentID, &g.KeyVersion, &g.SealedKey); err != nil {
			return nil, err
		}
		out[g.EnvironmentID] = &g
	}
	return out, rows.Err()
}

func accessOf(g *grantRow) string {
	switch {
	case g == nil:
		return ""
	case g.SealedKey == nil:
		return api.AccessPending
	}
	return api.AccessActive
}

func putGrant(ctx context.Context, q storage.Querier, g *grantRow, now time.Time) error {
	_, err := q.ExecContext(ctx, `INSERT INTO grants (environment_id, principal_type, principal_id, key_version, sealed_key, created_at)
		VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (environment_id, principal_type, principal_id)
		DO UPDATE SET key_version = excluded.key_version, sealed_key = excluded.sealed_key`,
		g.EnvironmentID, g.PrincipalType, g.PrincipalID, g.KeyVersion, g.SealedKey, storage.FormatTime(now))
	return err
}

// revokeGrants deletes a principal's grants (optionally limited to one
// project) and flags environments where it held a key for rotation.
func revokeGrants(ctx context.Context, q storage.Querier, ptype, pid, projectID string, rotate bool) error {
	scope := ``
	args := []any{ptype, pid}
	if projectID != "" {
		scope = ` AND environment_id IN (SELECT id FROM environments WHERE project_id = ?)`
		args = append(args, projectID)
	}
	if rotate {
		if _, err := q.ExecContext(ctx, `UPDATE environments SET needs_rotation = 1 WHERE id IN (
			SELECT environment_id FROM grants WHERE principal_type = ? AND principal_id = ? AND sealed_key IS NOT NULL`+scope+`)`, args...); err != nil {
			return err
		}
	}
	_, err := q.ExecContext(ctx, `DELETE FROM grants WHERE principal_type = ? AND principal_id = ?`+scope, args...)
	return err
}

type tokenRow struct {
	ID         string
	ProjectID  string
	Name       string
	PublicKey  []byte
	AuthHash   []byte
	ExpiresAt  time.Time
	CreatedBy  string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

func getToken(ctx context.Context, q storage.Querier, id string) (*tokenRow, error) {
	var t tokenRow
	var exp, created string
	var last sql.NullString
	err := q.QueryRowContext(ctx, `SELECT id, project_id, name, public_key, auth_hash, expires_at, created_by, created_at, last_used_at
		FROM tokens WHERE id = ?`, id).Scan(&t.ID, &t.ProjectID, &t.Name, &t.PublicKey, &t.AuthHash, &exp, &t.CreatedBy, &created, &last)
	if err != nil {
		return nil, storage.MapErr(err)
	}
	t.ExpiresAt, t.CreatedAt = storage.ParseTime(exp), storage.ParseTime(created)
	if last.Valid {
		lt := storage.ParseTime(last.String)
		t.LastUsedAt = &lt
	}
	return &t, nil
}

func (s *Server) audit(ctx context.Context, q storage.Querier, c *caller, projectID, action, env, detail string) error {
	_, err := q.ExecContext(ctx, `INSERT INTO audit (project_id, actor, action, environment, detail, ip, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, projectID, c.actor(), action, env, detail, c.ip, storage.FormatTime(s.now()))
	return err
}

// Sweep removes expired sessions, invites, memberships and tokens. Removed
// memberships and tokens flag their environments for key rotation. Access
// checks treat expired rows as absent on their own, so the sweep only
// affects cleanup and rotation flags.
func (s *Server) Sweep(ctx context.Context) error {
	now := storage.FormatTime(s.now())
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE refresh_expires_at <= ?`, now); err != nil {
			return err
		}
		type expired struct{ ptype, id, project string }
		var list []expired
		collect := func(query, ptype string) error {
			rows, err := tx.QueryContext(ctx, query, now)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				e := expired{ptype: ptype}
				if err := rows.Scan(&e.id, &e.project); err != nil {
					return err
				}
				list = append(list, e)
			}
			return rows.Err()
		}
		if err := collect(`SELECT user_id, project_id FROM members WHERE expires_at IS NOT NULL AND expires_at <= ?`, "user"); err != nil {
			return err
		}
		if err := collect(`SELECT id, project_id FROM tokens WHERE expires_at <= ?`, "token"); err != nil {
			return err
		}
		if err := collect(`SELECT id, project_id FROM invites WHERE expires_at <= ?`, "invite"); err != nil {
			return err
		}
		sys := &caller{}
		for _, e := range list {
			switch e.ptype {
			case "user":
				if err := revokeGrants(ctx, tx, "user", e.id, e.project, true); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `DELETE FROM members WHERE project_id = ? AND user_id = ?`, e.project, e.id); err != nil {
					return err
				}
				handle := e.id
				if u, err := getUser(ctx, tx, e.id); err == nil {
					handle = u.Handle
				}
				if err := s.audit(ctx, tx, sys, e.project, "member.expired", "", handle); err != nil {
					return err
				}
			case "token":
				if err := revokeGrants(ctx, tx, "token", e.id, "", true); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `DELETE FROM tokens WHERE id = ?`, e.id); err != nil {
					return err
				}
				if err := s.audit(ctx, tx, sys, e.project, "token.expired", "", e.id); err != nil {
					return err
				}
			case "invite":
				// The server never released these keys, so no rotation.
				if err := revokeGrants(ctx, tx, "invite", e.id, "", false); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `DELETE FROM invites WHERE id = ?`, e.id); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
