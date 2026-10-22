package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"slices"
	"strconv"

	"github.com/enigma-137/ven/internal/domain"
	"github.com/enigma-137/ven/internal/e2e"
	"github.com/enigma-137/ven/internal/envfile"
	"github.com/enigma-137/ven/internal/remote/api"
	"github.com/enigma-137/ven/internal/storage"
)

// sealedKeySize is the exact length of an environment key sealed with
// e2e.SealTo: ephemeral key, nonce, 32-byte key and GCM tag.
const sealedKeySize = e2e.KeySize + 12 + e2e.KeySize + 16

func (s *Server) routes() {
	m := s.mux
	v := api.Version
	m.HandleFunc("GET "+v+"/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })

	m.HandleFunc("POST "+v+"/auth/device", s.public(s.deviceStart))
	m.HandleFunc("POST "+v+"/auth/device/poll", s.public(s.devicePoll))
	m.HandleFunc("POST "+v+"/auth/refresh", s.public(s.refresh))
	m.HandleFunc("POST "+v+"/auth/logout", s.authed(maxBodyBytes, s.logout))

	m.HandleFunc("GET "+v+"/me", s.authed(maxBodyBytes, s.getMe))
	m.HandleFunc("PUT "+v+"/me/key", s.authed(maxBodyBytes, s.setKey))

	m.HandleFunc("GET "+v+"/projects", s.authed(maxBodyBytes, s.listProjects))
	m.HandleFunc("POST "+v+"/projects", s.authed(maxBodyBytes, s.createProject))
	p := v + "/projects/{owner}/{slug}"
	m.HandleFunc("GET "+p, s.authed(maxBodyBytes, s.getProjectHandler))
	m.HandleFunc("DELETE "+p, s.authed(maxBodyBytes, s.deleteProject))
	m.HandleFunc("POST "+p+"/environments", s.authed(maxBodyBytes, s.createEnvironment))
	m.HandleFunc("GET "+p+"/environments/{env}", s.authed(maxBodyBytes, s.getEnvironment))
	m.HandleFunc("PUT "+p+"/environments/{env}/content", s.authed(maxContentBodySize, s.putContent))
	m.HandleFunc("GET "+p+"/environments/{env}/recipients", s.authed(maxBodyBytes, s.listRecipients))
	m.HandleFunc("POST "+p+"/environments/{env}/rotate", s.authed(maxContentBodySize, s.rotate))

	m.HandleFunc("GET "+p+"/members", s.authed(maxBodyBytes, s.listMembers))
	m.HandleFunc("PATCH "+p+"/members/{handle}", s.authed(maxBodyBytes, s.updateMember))
	m.HandleFunc("DELETE "+p+"/members/{handle}", s.authed(maxBodyBytes, s.removeMember))
	m.HandleFunc("POST "+p+"/members/{handle}/approve", s.authed(maxBodyBytes, s.approveMember))

	m.HandleFunc("GET "+p+"/invites", s.authed(maxBodyBytes, s.listInvites))
	m.HandleFunc("POST "+p+"/invites", s.authed(maxBodyBytes, s.createInvite))
	m.HandleFunc("DELETE "+p+"/invites/{id}", s.authed(maxBodyBytes, s.revokeInvite))
	m.HandleFunc("POST "+v+"/invites/{id}/open", s.authed(maxBodyBytes, s.openInvite))
	m.HandleFunc("POST "+v+"/invites/{id}/accept", s.authed(maxBodyBytes, s.acceptInvite))

	m.HandleFunc("GET "+p+"/tokens", s.authed(maxBodyBytes, s.listTokens))
	m.HandleFunc("POST "+p+"/tokens", s.authed(maxBodyBytes, s.createToken))
	m.HandleFunc("DELETE "+p+"/tokens/{id}", s.authed(maxBodyBytes, s.revokeToken))
	m.HandleFunc("GET "+v+"/token", s.tokenAuthed(s.tokenState))

	m.HandleFunc("GET "+p+"/audit", s.authed(maxBodyBytes, s.listAudit))

	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, api.Error{Code: api.CodeNotFound, Message: "not found"})
	})
}

// projectCtx is a project the caller is a member of.
type projectCtx struct {
	project *projectRow
	member  *memberRow
}

func (pc *projectCtx) atLeast(role string) error {
	if api.RoleRank(pc.member.Role) < api.RoleRank(role) {
		return errForbidden
	}
	return nil
}

// loadProject resolves {owner}/{slug} for a member. Non-members get 404 so
// project names do not leak.
func (s *Server) loadProject(ctx context.Context, q storage.Querier, r *http.Request, c *caller) (*projectCtx, error) {
	p, err := getProject(ctx, q, r.PathValue("owner"), r.PathValue("slug"))
	if err != nil {
		return nil, err
	}
	m, err := getMember(ctx, q, p.ID, c.user.ID, s.now())
	if err != nil {
		return nil, err
	}
	return &projectCtx{project: p, member: m}, nil
}

// loadEnv resolves {env} and the caller's grant (nil when none).
func (s *Server) loadEnv(ctx context.Context, q storage.Querier, r *http.Request, c *caller, pc *projectCtx) (*envRow, *grantRow, error) {
	e, err := getEnv(ctx, q, pc.project.ID, r.PathValue("env"))
	if err != nil {
		return nil, nil, err
	}
	g, err := getGrant(ctx, q, e.ID, e2e.PrincipalUser, c.user.ID)
	if errors.Is(err, storage.ErrNotFound) {
		return e, nil, nil
	}
	return e, g, err
}

func requireActive(g *grantRow) error {
	if g == nil {
		return errorf(http.StatusForbidden, api.CodeForbidden, "you do not have access to this environment")
	}
	if g.SealedKey == nil {
		return errorf(http.StatusForbidden, api.CodeForbidden, "access to this protected environment is waiting for approval")
	}
	return nil
}

func (s *Server) projectAPI(ctx context.Context, q storage.Querier, p *projectRow, role string, ptype, pid string) (api.Project, error) {
	out := api.Project{ID: p.ID, Owner: p.Owner, Slug: p.Slug, Name: p.Name, Role: role, CreatedAt: p.CreatedAt, Environments: []api.Environment{}}
	envs, err := listEnvs(ctx, q, p.ID)
	if err != nil {
		return out, err
	}
	grants, err := grantsFor(ctx, q, ptype, pid)
	if err != nil {
		return out, err
	}
	for _, e := range envs {
		g := grants[e.ID]
		if ptype == e2e.PrincipalToken && g == nil {
			continue
		}
		out.Environments = append(out.Environments, e.api(accessOf(g)))
	}
	return out, nil
}

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request, c *caller) error {
	ctx := r.Context()
	rows, err := s.db.QueryContext(ctx, `SELECT project_id FROM members WHERE user_id = ?
		AND (expires_at IS NULL OR expires_at > ?)`, c.user.ID, storage.FormatTime(s.now()))
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	out := []api.Project{}
	for _, id := range ids {
		p, err := getProjectByID(ctx, s.db, id)
		if err != nil {
			return err
		}
		m, err := getMember(ctx, s.db, id, c.user.ID, s.now())
		if err != nil {
			continue
		}
		ap, err := s.projectAPI(ctx, s.db, p, m.Role, e2e.PrincipalUser, c.user.ID)
		if err != nil {
			return err
		}
		ap.MemberExpiresAt = m.ExpiresAt
		out = append(out, ap)
	}
	slices.SortFunc(out, func(a, b api.Project) int {
		if a.Ref() < b.Ref() {
			return -1
		}
		if a.Ref() > b.Ref() {
			return 1
		}
		return 0
	})
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) getProjectHandler(w http.ResponseWriter, r *http.Request, c *caller) error {
	ctx := r.Context()
	pc, err := s.loadProject(ctx, s.db, r, c)
	if err != nil {
		return err
	}
	ap, err := s.projectAPI(ctx, s.db, pc.project, pc.member.Role, e2e.PrincipalUser, c.user.ID)
	if err != nil {
		return err
	}
	ap.MemberExpiresAt = pc.member.ExpiresAt
	writeJSON(w, http.StatusOK, ap)
	return nil
}

func requireKey(c *caller) error {
	if c.user.PublicKey == nil {
		return errorf(http.StatusConflict, api.CodeNoKey, "set up your account key first (ven login)")
	}
	return nil
}

// defaultProtected marks production-like environments as protected.
func defaultProtected(slug string) bool {
	switch slug {
	case "production", "prod", "live":
		return true
	}
	return false
}

func (s *Server) validateNewEnv(req api.CreateEnvironmentRequest) (name, slug string, protected bool, err error) {
	if !e2e.ValidID(req.ID) {
		return "", "", false, invalid("environment id must be 32 lowercase hex characters")
	}
	name, err = domain.CleanName("environment name", req.Name, 64)
	if err != nil {
		return "", "", false, invalid("%v", err)
	}
	slug = domain.Slugify(name)
	protected = defaultProtected(slug)
	if req.Protected != nil {
		protected = *req.Protected
	}
	if len(req.SealedKey) != sealedKeySize {
		return "", "", false, invalid("sealed_key is malformed")
	}
	return name, slug, protected, nil
}

func insertEnv(ctx context.Context, tx *sql.Tx, projectID, envID, name, slug string, protected bool, now string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO environments (id, project_id, name, slug, protected, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, envID, projectID, name, slug, protected, now, now)
	if err != nil {
		if errors.Is(storage.MapErr(err), storage.ErrConflict) {
			return errorf(http.StatusConflict, api.CodeConflict, "environment %q already exists", slug)
		}
		return err
	}
	return nil
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request, c *caller) error {
	if err := requireKey(c); err != nil {
		return err
	}
	var req api.CreateProjectRequest
	if err := decode(r, maxBodyBytes, &req); err != nil {
		return err
	}
	if !e2e.ValidID(req.ID) {
		return invalid("project id must be 32 lowercase hex characters")
	}
	name, err := domain.CleanName("project name", req.Name, 100)
	if err != nil {
		return invalid("%v", err)
	}
	if len(req.Environments) > 50 {
		return invalid("too many environments")
	}
	slug := domain.Slugify(name)
	ctx := r.Context()
	nowT := s.now()
	now := storage.FormatTime(nowT)
	err = s.db.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO projects (id, owner_id, name, slug, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
			req.ID, c.user.ID, name, slug, now, now)
		if err != nil {
			if errors.Is(storage.MapErr(err), storage.ErrConflict) {
				return errorf(http.StatusConflict, api.CodeConflict, "you already have a project named %q", slug)
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO members (project_id, user_id, role, added_by, created_at) VALUES (?, ?, 'owner', ?, ?)`,
			req.ID, c.user.ID, c.user.Handle, now); err != nil {
			return err
		}
		for _, er := range req.Environments {
			ename, eslug, prot, err := s.validateNewEnv(er)
			if err != nil {
				return err
			}
			if err := insertEnv(ctx, tx, req.ID, er.ID, ename, eslug, prot, now); err != nil {
				return err
			}
			if err := putGrant(ctx, tx, &grantRow{EnvironmentID: er.ID, PrincipalType: e2e.PrincipalUser, PrincipalID: c.user.ID,
				KeyVersion: 1, SealedKey: er.SealedKey}, nowT); err != nil {
				return err
			}
		}
		return s.audit(ctx, tx, c, req.ID, "project.create", "", slug)
	})
	if err != nil {
		return err
	}
	p, err := getProjectByID(ctx, s.db, req.ID)
	if err != nil {
		return err
	}
	ap, err := s.projectAPI(ctx, s.db, p, api.RoleOwner, e2e.PrincipalUser, c.user.ID)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, ap)
	return nil
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request, c *caller) error {
	ctx := r.Context()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		pc, err := s.loadProject(ctx, tx, r, c)
		if err != nil {
			return err
		}
		if err := pc.atLeast(api.RoleOwner); err != nil {
			return err
		}
		// Environments, grants, members, invites and tokens cascade.
		if _, err := tx.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, pc.project.ID); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, c, pc.project.ID, "project.delete", "", pc.project.Slug); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}

func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request, c *caller) error {
	if err := requireKey(c); err != nil {
		return err
	}
	var req api.CreateEnvironmentRequest
	if err := decode(r, maxBodyBytes, &req); err != nil {
		return err
	}
	ctx := r.Context()
	nowT := s.now()
	var env *envRow
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		pc, err := s.loadProject(ctx, tx, r, c)
		if err != nil {
			return err
		}
		if err := pc.atLeast(api.RoleAdmin); err != nil {
			return err
		}
		name, slug, prot, err := s.validateNewEnv(req)
		if err != nil {
			return err
		}
		if err := insertEnv(ctx, tx, pc.project.ID, req.ID, name, slug, prot, storage.FormatTime(nowT)); err != nil {
			return err
		}
		if err := putGrant(ctx, tx, &grantRow{EnvironmentID: req.ID, PrincipalType: e2e.PrincipalUser, PrincipalID: c.user.ID,
			KeyVersion: 1, SealedKey: req.SealedKey}, nowT); err != nil {
			return err
		}
		if env, err = getEnvByID(ctx, tx, req.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, c, pc.project.ID, "environment.create", slug, "")
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, env.api(api.AccessActive))
	return nil
}

func envState(projectID string, e *envRow, g *grantRow) api.EnvironmentState {
	st := api.EnvironmentState{ProjectID: projectID, Environment: e.api(accessOf(g))}
	if g != nil && g.SealedKey != nil && g.KeyVersion == e.KeyVersion {
		st.SealedKey = g.SealedKey
	}
	if e.Content != nil {
		st.Content = &api.Content{Nonce: e.Nonce, Ciphertext: e.Content}
	}
	return st
}

func (s *Server) getEnvironment(w http.ResponseWriter, r *http.Request, c *caller) error {
	ctx := r.Context()
	var st api.EnvironmentState
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		pc, err := s.loadProject(ctx, tx, r, c)
		if err != nil {
			return err
		}
		e, g, err := s.loadEnv(ctx, tx, r, c, pc)
		if err != nil {
			return err
		}
		if err := requireActive(g); err != nil {
			return err
		}
		st = envState(pc.project.ID, e, g)
		if st.Content != nil {
			return s.audit(ctx, tx, c, pc.project.ID, "environment.pull", e.Slug, revisionDetail(e.Revision))
		}
		return nil
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, st)
	return nil
}

func revisionDetail(rev int) string { return "revision " + strconv.Itoa(rev) }

func validContent(ct *api.Content) error {
	if ct == nil || len(ct.Nonce) != 12 || len(ct.Ciphertext) < 16 || len(ct.Ciphertext) > envfile.MaxFileSize+16 {
		return invalid("content is malformed or too large")
	}
	return nil
}

func (s *Server) putContent(w http.ResponseWriter, r *http.Request, c *caller) error {
	var req api.PutContentRequest
	if err := decode(r, maxContentBodySize, &req); err != nil {
		return err
	}
	if err := validContent(&req.Content); err != nil {
		return err
	}
	ctx := r.Context()
	var out api.Environment
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		pc, err := s.loadProject(ctx, tx, r, c)
		if err != nil {
			return err
		}
		if err := pc.atLeast(api.RoleDeveloper); err != nil {
			return err
		}
		e, g, err := s.loadEnv(ctx, tx, r, c, pc)
		if err != nil {
			return err
		}
		if err := requireActive(g); err != nil {
			return err
		}
		if e.NeedsRotation {
			return errorf(http.StatusConflict, api.CodeRotationRequired, "someone lost access to %s; its key must be rotated before new values are written", e.Slug)
		}
		if req.BaseRevision != e.Revision || req.KeyVersion != e.KeyVersion {
			return errorf(http.StatusConflict, api.CodeStale, "%s changed since you last pulled it (now at revision %d); pull and try again", e.Slug, e.Revision)
		}
		now := storage.FormatTime(s.now())
		if _, err := tx.ExecContext(ctx, `UPDATE environments SET revision = revision + 1, content_nonce = ?, content = ?, updated_at = ?
			WHERE id = ?`, req.Content.Nonce, req.Content.Ciphertext, now, e.ID); err != nil {
			return err
		}
		if e, err = getEnvByID(ctx, tx, e.ID); err != nil {
			return err
		}
		out = e.api(api.AccessActive)
		return s.audit(ctx, tx, c, pc.project.ID, "environment.push", e.Slug, revisionDetail(e.Revision))
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// recipients lists the principals that hold the environment key (active
// grants): exactly the set a rotation must re-seal to.
func recipients(ctx context.Context, q storage.Querier, envID string) ([]api.Recipient, error) {
	rows, err := q.QueryContext(ctx, `SELECT g.principal_type, g.principal_id,
		COALESCE(u.handle, t.name, i.handle, ''), COALESCE(u.public_key, t.public_key, i.public_key)
		FROM grants g
		LEFT JOIN users u ON g.principal_type = 'user' AND u.id = g.principal_id
		LEFT JOIN tokens t ON g.principal_type = 'token' AND t.id = g.principal_id
		LEFT JOIN invites i ON g.principal_type = 'invite' AND i.id = g.principal_id
		WHERE g.environment_id = ? AND g.sealed_key IS NOT NULL
		ORDER BY g.principal_type, g.principal_id`, envID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []api.Recipient{}
	for rows.Next() {
		var rc api.Recipient
		if err := rows.Scan(&rc.Type, &rc.ID, &rc.Label, &rc.PublicKey); err != nil {
			return nil, err
		}
		out = append(out, rc)
	}
	return out, rows.Err()
}

func (s *Server) listRecipients(w http.ResponseWriter, r *http.Request, c *caller) error {
	ctx := r.Context()
	pc, err := s.loadProject(ctx, s.db, r, c)
	if err != nil {
		return err
	}
	e, g, err := s.loadEnv(ctx, s.db, r, c, pc)
	if err != nil {
		return err
	}
	if err := requireActive(g); err != nil {
		return err
	}
	list, err := recipients(ctx, s.db, e.ID)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, list)
	return nil
}

func (s *Server) rotate(w http.ResponseWriter, r *http.Request, c *caller) error {
	var req api.RotateRequest
	if err := decode(r, maxContentBodySize, &req); err != nil {
		return err
	}
	ctx := r.Context()
	var out api.Environment
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		pc, err := s.loadProject(ctx, tx, r, c)
		if err != nil {
			return err
		}
		if err := pc.atLeast(api.RoleDeveloper); err != nil {
			return err
		}
		e, g, err := s.loadEnv(ctx, tx, r, c, pc)
		if err != nil {
			return err
		}
		if err := requireActive(g); err != nil {
			return err
		}
		if req.FromKeyVersion != e.KeyVersion || req.BaseRevision != e.Revision {
			return errorf(http.StatusConflict, api.CodeStale, "%s changed since you last pulled it; pull and try again", e.Slug)
		}
		if (e.Content == nil) != (req.Content == nil) {
			return invalid("content must be re-encrypted exactly when the environment has content")
		}
		if req.Content != nil {
			if err := validContent(req.Content); err != nil {
				return err
			}
		}
		current, err := recipients(ctx, tx, e.ID)
		if err != nil {
			return err
		}
		newVersion := e.KeyVersion + 1
		want := map[string]bool{}
		for _, rc := range current {
			want[rc.Type+":"+rc.ID] = true
		}
		if len(req.Keys) != len(want) {
			return errorf(http.StatusConflict, api.CodeStale, "the recipients of %s changed; pull and try again", e.Slug)
		}
		now := s.now()
		for _, k := range req.Keys {
			id := k.PrincipalType + ":" + k.PrincipalID
			if !want[id] || k.EnvironmentID != e.ID || k.KeyVersion != newVersion || len(k.SealedKey) != sealedKeySize {
				return errorf(http.StatusConflict, api.CodeStale, "the recipients of %s changed; pull and try again", e.Slug)
			}
			delete(want, id)
			if err := putGrant(ctx, tx, &grantRow{EnvironmentID: e.ID, PrincipalType: k.PrincipalType, PrincipalID: k.PrincipalID,
				KeyVersion: newVersion, SealedKey: k.SealedKey}, now); err != nil {
				return err
			}
		}
		var nonce, content []byte
		if req.Content != nil {
			nonce, content = req.Content.Nonce, req.Content.Ciphertext
		}
		if _, err := tx.ExecContext(ctx, `UPDATE environments SET key_version = ?, revision = revision + 1, content_nonce = ?,
			content = ?, needs_rotation = 0, updated_at = ? WHERE id = ?`, newVersion, nonce, content, storage.FormatTime(now), e.ID); err != nil {
			return err
		}
		if e, err = getEnvByID(ctx, tx, e.ID); err != nil {
			return err
		}
		out = e.api(api.AccessActive)
		return s.audit(ctx, tx, c, pc.project.ID, "environment.rotate", e.Slug, "key version "+strconv.Itoa(newVersion))
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}
