package storage

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// VaultConfig is the singleton row describing vault encryption metadata.
type VaultConfig struct {
	VaultID         string
	FormatVersion   int
	KDFAlgorithm    string
	KDFVersion      int
	KDFMemoryKiB    uint32
	KDFIterations   uint32
	KDFParallelism  uint8
	KDFSalt         []byte
	WrappedKeyNonce []byte
	WrappedKey      []byte
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// GetVaultConfig returns ErrNotFound when the vault has not been initialized.
func GetVaultConfig(ctx context.Context, q Querier) (*VaultConfig, error) {
	var c VaultConfig
	var created, updated string
	err := q.QueryRowContext(ctx, `SELECT vault_id, format_version, kdf_algorithm, kdf_version,
		kdf_memory_kib, kdf_iterations, kdf_parallelism, kdf_salt, wrapped_key_nonce, wrapped_key,
		created_at, updated_at FROM vault_config WHERE id = 1`).Scan(
		&c.VaultID, &c.FormatVersion, &c.KDFAlgorithm, &c.KDFVersion,
		&c.KDFMemoryKiB, &c.KDFIterations, &c.KDFParallelism, &c.KDFSalt, &c.WrappedKeyNonce, &c.WrappedKey,
		&created, &updated)
	if err != nil {
		return nil, mapErr(err)
	}
	c.CreatedAt, c.UpdatedAt = ParseTime(created), ParseTime(updated)
	return &c, nil
}

// InsertVaultConfig creates the singleton row; ErrConflict if it exists.
func InsertVaultConfig(ctx context.Context, q Querier, c *VaultConfig) error {
	_, err := q.ExecContext(ctx, `INSERT INTO vault_config (id, vault_id, format_version, kdf_algorithm,
		kdf_version, kdf_memory_kib, kdf_iterations, kdf_parallelism, kdf_salt, wrapped_key_nonce,
		wrapped_key, created_at, updated_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.VaultID, c.FormatVersion, c.KDFAlgorithm, c.KDFVersion, c.KDFMemoryKiB, c.KDFIterations,
		c.KDFParallelism, c.KDFSalt, c.WrappedKeyNonce, c.WrappedKey, FormatTime(c.CreatedAt), FormatTime(c.UpdatedAt))
	if err != nil && strings.Contains(err.Error(), "constraint failed") {
		return ErrConflict
	}
	return mapErr(err)
}

// UpdateVaultKey replaces the KDF parameters and wrapped key (password change).
func UpdateVaultKey(ctx context.Context, q Querier, c *VaultConfig) error {
	res, err := q.ExecContext(ctx, `UPDATE vault_config SET kdf_version = ?, kdf_memory_kib = ?,
		kdf_iterations = ?, kdf_parallelism = ?, kdf_salt = ?, wrapped_key_nonce = ?, wrapped_key = ?,
		updated_at = ? WHERE id = 1`,
		c.KDFVersion, c.KDFMemoryKiB, c.KDFIterations, c.KDFParallelism, c.KDFSalt, c.WrappedKeyNonce,
		c.WrappedKey, FormatTime(c.UpdatedAt))
	if err != nil {
		return err
	}
	return requireOne(res)
}

// GetSetting returns ErrNotFound when the key is unset.
func GetSetting(ctx context.Context, q Querier, key string) (string, error) {
	var v string
	err := q.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	return v, mapErr(err)
}

// SetSetting upserts a setting.
func SetSetting(ctx context.Context, q Querier, key, value string) error {
	_, err := q.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// Project is a project row plus derived counts.
type Project struct {
	ID               string
	Name             string
	Slug             string
	Description      string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	EnvironmentCount int
}

const projectSelect = `SELECT p.id, p.name, p.slug, p.description, p.created_at, p.updated_at,
	(SELECT COUNT(*) FROM environments e WHERE e.project_id = p.id) FROM projects p`

func scanProject(s interface{ Scan(...any) error }) (Project, error) {
	var p Project
	var created, updated string
	err := s.Scan(&p.ID, &p.Name, &p.Slug, &p.Description, &created, &updated, &p.EnvironmentCount)
	p.CreatedAt, p.UpdatedAt = ParseTime(created), ParseTime(updated)
	return p, err
}

// ListProjects returns all projects ordered by name.
func ListProjects(ctx context.Context, q Querier) ([]Project, error) {
	rows, err := q.QueryContext(ctx, projectSelect+` ORDER BY p.name COLLATE NOCASE, p.slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetProjectBySlug looks up a project by slug.
func GetProjectBySlug(ctx context.Context, q Querier, slug string) (Project, error) {
	p, err := scanProject(q.QueryRowContext(ctx, projectSelect+` WHERE p.slug = ?`, slug))
	return p, mapErr(err)
}

// GetProjectByID looks up a project by ID.
func GetProjectByID(ctx context.Context, q Querier, id string) (Project, error) {
	p, err := scanProject(q.QueryRowContext(ctx, projectSelect+` WHERE p.id = ?`, id))
	return p, mapErr(err)
}

// FindProjectsByName matches names case-insensitively.
func FindProjectsByName(ctx context.Context, q Querier, name string) ([]Project, error) {
	rows, err := q.QueryContext(ctx, projectSelect+` WHERE p.name = ? COLLATE NOCASE`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// InsertProject inserts p.
func InsertProject(ctx context.Context, q Querier, p *Project) error {
	_, err := q.ExecContext(ctx, `INSERT INTO projects (id, name, slug, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`, p.ID, p.Name, p.Slug, p.Description, FormatTime(p.CreatedAt), FormatTime(p.UpdatedAt))
	return mapErr(err)
}

// UpdateProject writes name, slug, description and updated_at.
func UpdateProject(ctx context.Context, q Querier, p *Project) error {
	res, err := q.ExecContext(ctx, `UPDATE projects SET name = ?, slug = ?, description = ?, updated_at = ? WHERE id = ?`,
		p.Name, p.Slug, p.Description, FormatTime(p.UpdatedAt), p.ID)
	if err != nil {
		return mapErr(err)
	}
	return requireOne(res)
}

// TouchProject bumps updated_at.
func TouchProject(ctx context.Context, q Querier, id string, t time.Time) error {
	_, err := q.ExecContext(ctx, `UPDATE projects SET updated_at = ? WHERE id = ?`, FormatTime(t), id)
	return err
}

// DeleteProject deletes a project; environments and variables cascade.
func DeleteProject(ctx context.Context, q Querier, id string) error {
	res, err := q.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return requireOne(res)
}

// Environment is an environment row plus derived counts.
type Environment struct {
	ID            string
	ProjectID     string
	Name          string
	Slug          string
	SortOrder     int
	CreatedAt     time.Time
	UpdatedAt     time.Time
	VariableCount int
}

const environmentSelect = `SELECT e.id, e.project_id, e.name, e.slug, e.sort_order, e.created_at, e.updated_at,
	(SELECT COUNT(*) FROM variables v WHERE v.environment_id = e.id) FROM environments e`

func scanEnvironment(s interface{ Scan(...any) error }) (Environment, error) {
	var e Environment
	var created, updated string
	err := s.Scan(&e.ID, &e.ProjectID, &e.Name, &e.Slug, &e.SortOrder, &created, &updated, &e.VariableCount)
	e.CreatedAt, e.UpdatedAt = ParseTime(created), ParseTime(updated)
	return e, err
}

// ListEnvironments returns a project's environments in display order.
func ListEnvironments(ctx context.Context, q Querier, projectID string) ([]Environment, error) {
	rows, err := q.QueryContext(ctx, environmentSelect+` WHERE e.project_id = ? ORDER BY e.sort_order, e.name`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Environment
	for rows.Next() {
		e, err := scanEnvironment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetEnvironmentBySlug looks up an environment within a project.
func GetEnvironmentBySlug(ctx context.Context, q Querier, projectID, slug string) (Environment, error) {
	e, err := scanEnvironment(q.QueryRowContext(ctx, environmentSelect+` WHERE e.project_id = ? AND e.slug = ?`, projectID, slug))
	return e, mapErr(err)
}

// GetEnvironmentByID looks up an environment by ID.
func GetEnvironmentByID(ctx context.Context, q Querier, id string) (Environment, error) {
	e, err := scanEnvironment(q.QueryRowContext(ctx, environmentSelect+` WHERE e.id = ?`, id))
	return e, mapErr(err)
}

// NextEnvironmentOrder returns the sort order for a new environment.
func NextEnvironmentOrder(ctx context.Context, q Querier, projectID string) (int, error) {
	var n sql.NullInt64
	err := q.QueryRowContext(ctx, `SELECT MAX(sort_order) FROM environments WHERE project_id = ?`, projectID).Scan(&n)
	if !n.Valid {
		return 0, err
	}
	return int(n.Int64) + 1, err
}

// InsertEnvironment inserts e.
func InsertEnvironment(ctx context.Context, q Querier, e *Environment) error {
	_, err := q.ExecContext(ctx, `INSERT INTO environments (id, project_id, name, slug, sort_order, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, e.ID, e.ProjectID, e.Name, e.Slug, e.SortOrder, FormatTime(e.CreatedAt), FormatTime(e.UpdatedAt))
	return mapErr(err)
}

// UpdateEnvironment writes name, slug and updated_at.
func UpdateEnvironment(ctx context.Context, q Querier, e *Environment) error {
	res, err := q.ExecContext(ctx, `UPDATE environments SET name = ?, slug = ?, updated_at = ? WHERE id = ?`,
		e.Name, e.Slug, FormatTime(e.UpdatedAt), e.ID)
	if err != nil {
		return mapErr(err)
	}
	return requireOne(res)
}

// TouchEnvironment bumps updated_at on an environment and its project.
func TouchEnvironment(ctx context.Context, q Querier, id string, t time.Time) error {
	ts := FormatTime(t)
	if _, err := q.ExecContext(ctx, `UPDATE environments SET updated_at = ? WHERE id = ?`, ts, id); err != nil {
		return err
	}
	_, err := q.ExecContext(ctx, `UPDATE projects SET updated_at = ? WHERE id = (SELECT project_id FROM environments WHERE id = ?)`, ts, id)
	return err
}

// DeleteEnvironment deletes an environment; variables cascade.
func DeleteEnvironment(ctx context.Context, q Querier, id string) error {
	res, err := q.ExecContext(ctx, `DELETE FROM environments WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return requireOne(res)
}

// Variable is a variable row. Ciphertext and Nonce hold the encrypted value.
type Variable struct {
	ID            string
	EnvironmentID string
	Key           string
	Ciphertext    []byte
	Nonce         []byte
	EncVersion    int
	DisplayType   string
	Description   string
	SortOrder     int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

const variableSelect = `SELECT id, environment_id, key, value_ciphertext, value_nonce, enc_version,
	display_type, description, sort_order, created_at, updated_at FROM variables`

func scanVariable(s interface{ Scan(...any) error }) (Variable, error) {
	var v Variable
	var created, updated string
	err := s.Scan(&v.ID, &v.EnvironmentID, &v.Key, &v.Ciphertext, &v.Nonce, &v.EncVersion,
		&v.DisplayType, &v.Description, &v.SortOrder, &created, &updated)
	v.CreatedAt, v.UpdatedAt = ParseTime(created), ParseTime(updated)
	return v, err
}

// ListVariables returns an environment's variables in display order. A
// non-empty search matches key or description case-insensitively.
func ListVariables(ctx context.Context, q Querier, envID, search string) ([]Variable, error) {
	query := variableSelect + ` WHERE environment_id = ?`
	args := []any{envID}
	if search = strings.TrimSpace(search); search != "" {
		pattern := "%" + escapeLike(strings.ToLower(search)) + "%"
		query += ` AND (lower(key) LIKE ? ESCAPE '\' OR lower(description) LIKE ? ESCAPE '\')`
		args = append(args, pattern, pattern)
	}
	query += ` ORDER BY sort_order, key`
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Variable
	for rows.Next() {
		v, err := scanVariable(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetVariableByKey looks up a variable by key within an environment.
func GetVariableByKey(ctx context.Context, q Querier, envID, key string) (Variable, error) {
	v, err := scanVariable(q.QueryRowContext(ctx, variableSelect+` WHERE environment_id = ? AND key = ?`, envID, key))
	return v, mapErr(err)
}

// GetVariableByID looks up a variable by ID.
func GetVariableByID(ctx context.Context, q Querier, id string) (Variable, error) {
	v, err := scanVariable(q.QueryRowContext(ctx, variableSelect+` WHERE id = ?`, id))
	return v, mapErr(err)
}

// NextVariableOrder returns the sort order for a new variable.
func NextVariableOrder(ctx context.Context, q Querier, envID string) (int, error) {
	var n sql.NullInt64
	err := q.QueryRowContext(ctx, `SELECT MAX(sort_order) FROM variables WHERE environment_id = ?`, envID).Scan(&n)
	if !n.Valid {
		return 0, err
	}
	return int(n.Int64) + 1, err
}

// InsertVariable inserts v.
func InsertVariable(ctx context.Context, q Querier, v *Variable) error {
	_, err := q.ExecContext(ctx, `INSERT INTO variables (id, environment_id, key, value_ciphertext, value_nonce,
		enc_version, display_type, description, sort_order, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.EnvironmentID, v.Key, v.Ciphertext, v.Nonce, v.EncVersion, v.DisplayType, v.Description,
		v.SortOrder, FormatTime(v.CreatedAt), FormatTime(v.UpdatedAt))
	return mapErr(err)
}

// UpdateVariable writes every mutable column of v.
func UpdateVariable(ctx context.Context, q Querier, v *Variable) error {
	res, err := q.ExecContext(ctx, `UPDATE variables SET key = ?, value_ciphertext = ?, value_nonce = ?,
		enc_version = ?, display_type = ?, description = ?, sort_order = ?, updated_at = ? WHERE id = ?`,
		v.Key, v.Ciphertext, v.Nonce, v.EncVersion, v.DisplayType, v.Description, v.SortOrder,
		FormatTime(v.UpdatedAt), v.ID)
	if err != nil {
		return mapErr(err)
	}
	return requireOne(res)
}

// DeleteVariable deletes a variable by ID.
func DeleteVariable(ctx context.Context, q Querier, id string) error {
	res, err := q.ExecContext(ctx, `DELETE FROM variables WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return requireOne(res)
}

// CountProjects returns the number of projects.
func CountProjects(ctx context.Context, q Querier) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects`).Scan(&n)
	return n, err
}

func requireOne(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
