package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/enigma-137/ven/internal/domain"
	"github.com/enigma-137/ven/internal/e2e"
	"github.com/enigma-137/ven/internal/remote/api"
	"github.com/enigma-137/ven/internal/storage"
)

func timePtr(s sql.NullString) *time.Time {
	if !s.Valid {
		return nil
	}
	t := storage.ParseTime(s.String)
	return &t
}

func formatTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return storage.FormatTime(*t)
}

// memberExpiry validates a requested membership end date. nil means no
// expiry, which must be asked for explicitly.
func (s *Server) memberExpiry(at *time.Time, noExpiry bool) (*time.Time, error) {
	now := s.now()
	if noExpiry {
		if at != nil {
			return nil, invalid("pass either an expiry or no_expiry, not both")
		}
		return nil, nil
	}
	if at == nil {
		t := now.Add(DefaultMemberTTL)
		return &t, nil
	}
	t := at.UTC().Truncate(time.Millisecond)
	if !t.After(now) || t.After(now.Add(MaxMemberTTL)) {
		return nil, invalid("membership expiry must be in the future and at most a year away")
	}
	return &t, nil
}

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request, c *caller) error {
	ctx := r.Context()
	pc, err := s.loadProject(ctx, s.db, r, c)
	if err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT m.user_id, m.role, m.expires_at, m.created_at FROM members m
		JOIN users u ON u.id = m.user_id WHERE m.project_id = ? AND (m.expires_at IS NULL OR m.expires_at > ?)
		ORDER BY u.handle`, pc.project.ID, storage.FormatTime(s.now()))
	if err != nil {
		return err
	}
	type row struct {
		userID, role, created string
		exp                   sql.NullString
	}
	var list []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.userID, &x.role, &x.exp, &x.created); err != nil {
			rows.Close()
			return err
		}
		list = append(list, x)
	}
	rows.Close()
	envs, err := listEnvs(ctx, s.db, pc.project.ID)
	if err != nil {
		return err
	}
	out := []api.Member{}
	for _, x := range list {
		u, err := getUser(ctx, s.db, x.userID)
		if err != nil {
			return err
		}
		grants, err := grantsFor(ctx, s.db, e2e.PrincipalUser, x.userID)
		if err != nil {
			return err
		}
		m := api.Member{User: u.api(), Role: x.role, ExpiresAt: timePtr(x.exp), CreatedAt: storage.ParseTime(x.created), Environments: []api.MemberEnvironment{}}
		for _, e := range envs {
			if g := grants[e.ID]; g != nil {
				m.Environments = append(m.Environments, api.MemberEnvironment{ID: e.ID, Slug: e.Slug, Access: accessOf(g)})
			}
		}
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// loadTarget resolves {handle} to a current member of the project.
func (s *Server) loadTarget(ctx context.Context, q storage.Querier, r *http.Request, pc *projectCtx) (*userRow, *memberRow, error) {
	u, err := getUserByHandle(ctx, q, r.PathValue("handle"))
	if err != nil {
		return nil, nil, err
	}
	m, err := getMember(ctx, q, pc.project.ID, u.ID, s.now())
	if err != nil {
		return nil, nil, err
	}
	return u, m, nil
}

func (s *Server) updateMember(w http.ResponseWriter, r *http.Request, c *caller) error {
	var req api.UpdateMemberRequest
	if err := decode(r, maxBodyBytes, &req); err != nil {
		return err
	}
	ctx := r.Context()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		pc, err := s.loadProject(ctx, tx, r, c)
		if err != nil {
			return err
		}
		if err := pc.atLeast(api.RoleAdmin); err != nil {
			return err
		}
		u, m, err := s.loadTarget(ctx, tx, r, pc)
		if err != nil {
			return err
		}
		if m.Role == api.RoleOwner {
			return errorf(http.StatusForbidden, api.CodeForbidden, "the project owner cannot be changed")
		}
		var details []string
		if req.Role != "" {
			if api.RoleRank(req.Role) == 0 || req.Role == api.RoleOwner || api.RoleRank(req.Role) > api.RoleRank(pc.member.Role) {
				return invalid("role must be viewer, developer or admin (and not above your own)")
			}
			if _, err := tx.ExecContext(ctx, `UPDATE members SET role = ? WHERE project_id = ? AND user_id = ?`, req.Role, pc.project.ID, u.ID); err != nil {
				return err
			}
			details = append(details, "role "+req.Role)
		}
		if req.ExpiresAt != nil || req.NoExpiry {
			exp, err := s.memberExpiry(req.ExpiresAt, req.NoExpiry)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE members SET expires_at = ? WHERE project_id = ? AND user_id = ?`,
				formatTimePtr(exp), pc.project.ID, u.ID); err != nil {
				return err
			}
			if exp == nil {
				details = append(details, "no expiry")
			} else {
				details = append(details, "expires "+exp.Format(time.DateOnly))
			}
		}
		if len(details) == 0 {
			return invalid("nothing to change")
		}
		if err := s.audit(ctx, tx, c, pc.project.ID, "member.update", "", u.Handle+": "+strings.Join(details, ", ")); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request, c *caller) error {
	ctx := r.Context()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		pc, err := s.loadProject(ctx, tx, r, c)
		if err != nil {
			return err
		}
		u, m, err := s.loadTarget(ctx, tx, r, pc)
		if err != nil {
			return err
		}
		if u.ID != c.user.ID {
			if err := pc.atLeast(api.RoleAdmin); err != nil {
				return err
			}
		}
		if m.Role == api.RoleOwner {
			return errorf(http.StatusForbidden, api.CodeForbidden, "the project owner cannot be removed; delete the project instead")
		}
		if err := revokeGrants(ctx, tx, e2e.PrincipalUser, u.ID, pc.project.ID, true); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM members WHERE project_id = ? AND user_id = ?`, pc.project.ID, u.ID); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, c, pc.project.ID, "member.remove", "", u.Handle); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}

func (s *Server) approveMember(w http.ResponseWriter, r *http.Request, c *caller) error {
	var req api.ApproveRequest
	if err := decode(r, maxBodyBytes, &req); err != nil {
		return err
	}
	if len(req.Keys) == 0 {
		return invalid("keys are required")
	}
	ctx := r.Context()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		pc, err := s.loadProject(ctx, tx, r, c)
		if err != nil {
			return err
		}
		if err := pc.atLeast(api.RoleAdmin); err != nil {
			return err
		}
		u, _, err := s.loadTarget(ctx, tx, r, pc)
		if err != nil {
			return err
		}
		now := s.now()
		var slugs []string
		for _, k := range req.Keys {
			e, err := getEnvByID(ctx, tx, k.EnvironmentID)
			if err != nil || e.ProjectID != pc.project.ID {
				return invalid("unknown environment")
			}
			mine, err := getGrant(ctx, tx, e.ID, e2e.PrincipalUser, c.user.ID)
			if err != nil || mine.SealedKey == nil {
				return errorf(http.StatusForbidden, api.CodeForbidden, "you do not have access to %s", e.Slug)
			}
			theirs, err := getGrant(ctx, tx, e.ID, e2e.PrincipalUser, u.ID)
			if err != nil || theirs.SealedKey != nil {
				return invalid("%s has no pending access to %s", u.Handle, e.Slug)
			}
			if k.PrincipalType != e2e.PrincipalUser || k.PrincipalID != u.ID || k.KeyVersion != e.KeyVersion || len(k.SealedKey) != sealedKeySize {
				return errorf(http.StatusConflict, api.CodeStale, "%s changed; try again", e.Slug)
			}
			if err := putGrant(ctx, tx, &grantRow{EnvironmentID: e.ID, PrincipalType: e2e.PrincipalUser, PrincipalID: u.ID,
				KeyVersion: e.KeyVersion, SealedKey: k.SealedKey}, now); err != nil {
				return err
			}
			slugs = append(slugs, e.Slug)
		}
		if err := s.audit(ctx, tx, c, pc.project.ID, "member.approve", strings.Join(slugs, ","), u.Handle); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}

func validHandle(h string) bool {
	if h == "" || len(h) > 100 {
		return false
	}
	for _, r := range h {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '/' {
			return false
		}
	}
	return true
}

type inviteRow struct {
	ID              string
	ProjectID       string
	Provider        string
	Handle          string
	UserID          sql.NullString
	Role            string
	AuthHash        []byte
	MemberExpiresAt *time.Time
	ExpiresAt       time.Time
	CreatedBy       string
}

func getInvite(ctx context.Context, q storage.Querier, id string) (*inviteRow, error) {
	var iv inviteRow
	var mexp sql.NullString
	var exp string
	err := q.QueryRowContext(ctx, `SELECT id, project_id, provider, handle, user_id, role, auth_hash, member_expires_at, expires_at, created_by
		FROM invites WHERE id = ?`, id).Scan(&iv.ID, &iv.ProjectID, &iv.Provider, &iv.Handle, &iv.UserID, &iv.Role, &iv.AuthHash, &mexp, &exp, &iv.CreatedBy)
	if err != nil {
		return nil, storage.MapErr(err)
	}
	iv.MemberExpiresAt, iv.ExpiresAt = timePtr(mexp), storage.ParseTime(exp)
	return &iv, nil
}

func (s *Server) inviteAPI(ctx context.Context, q storage.Querier, iv *inviteRow, withKeys bool) (api.Invite, error) {
	p, err := getProjectByID(ctx, q, iv.ProjectID)
	if err != nil {
		return api.Invite{}, err
	}
	out := api.Invite{ID: iv.ID, ProjectID: p.ID, Project: p.Owner + "/" + p.Slug, ProjectName: p.Name, Provider: iv.Provider,
		Handle: iv.Handle, Role: iv.Role, InvitedBy: iv.CreatedBy, ExpiresAt: iv.ExpiresAt, MemberExpiresAt: iv.MemberExpiresAt,
		Environments: []api.InviteEnvironment{}}
	grants, err := grantsFor(ctx, q, e2e.PrincipalInvite, iv.ID)
	if err != nil {
		return out, err
	}
	envs, err := listEnvs(ctx, q, p.ID)
	if err != nil {
		return out, err
	}
	for _, e := range envs {
		g := grants[e.ID]
		if g == nil {
			continue
		}
		ie := api.InviteEnvironment{ID: e.ID, Slug: e.Slug, Protected: g.SealedKey == nil, KeyVersion: g.KeyVersion}
		if withKeys {
			ie.SealedKey = g.SealedKey
		}
		out.Environments = append(out.Environments, ie)
	}
	return out, nil
}

func (s *Server) createInvite(w http.ResponseWriter, r *http.Request, c *caller) error {
	var req api.CreateInviteRequest
	if err := decode(r, maxBodyBytes, &req); err != nil {
		return err
	}
	if !e2e.ValidID(req.ID) {
		return invalid("invite id must be 32 lowercase hex characters")
	}
	if req.Provider == "" {
		req.Provider = "github"
	}
	if _, ok := s.providers[req.Provider]; !ok {
		return invalid("unsupported provider %q", req.Provider)
	}
	req.Handle = strings.TrimPrefix(strings.TrimSpace(req.Handle), "@")
	if !validHandle(req.Handle) {
		return invalid("handle is invalid")
	}
	if _, err := e2e.ParsePublicKey(req.PublicKey); err != nil || len(req.AuthHash) != 32 {
		return invalid("public_key or auth_hash is malformed")
	}
	if len(req.EnvironmentIDs) == 0 || len(req.EnvironmentIDs) > 50 {
		return invalid("choose at least one environment")
	}
	ttl := DefaultInviteTTL
	if req.TTLSeconds != 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
		if ttl < time.Minute || ttl > MaxInviteTTL {
			return invalid("invite lifetime must be between 1 minute and 7 days")
		}
	}
	memberExp, err := s.memberExpiry(req.MemberExpiresAt, req.NoExpiry)
	if err != nil {
		return err
	}
	ctx := r.Context()
	var out api.Invite
	err = s.db.WithTx(ctx, func(tx *sql.Tx) error {
		pc, err := s.loadProject(ctx, tx, r, c)
		if err != nil {
			return err
		}
		if err := pc.atLeast(api.RoleAdmin); err != nil {
			return err
		}
		if api.RoleRank(req.Role) == 0 || req.Role == api.RoleOwner || api.RoleRank(req.Role) > api.RoleRank(pc.member.Role) {
			return invalid("role must be viewer, developer or admin (and not above your own)")
		}
		var userID any
		if u, err := getUserByHandle(ctx, tx, req.Handle); err == nil && u.Provider == req.Provider {
			if m, err := getMember(ctx, tx, pc.project.ID, u.ID, s.now()); err == nil && m.Role == api.RoleOwner {
				return invalid("%s owns this project", u.Handle)
			}
			userID = u.ID
		}
		keys := map[string]api.SealedKey{}
		for _, k := range req.Keys {
			if _, dup := keys[k.EnvironmentID]; dup {
				return invalid("duplicate key for an environment")
			}
			keys[k.EnvironmentID] = k
		}
		now := s.now()
		seen := map[string]bool{}
		var grants []*grantRow
		for _, envID := range req.EnvironmentIDs {
			if seen[envID] {
				return invalid("duplicate environment")
			}
			seen[envID] = true
			e, err := getEnvByID(ctx, tx, envID)
			if err != nil || e.ProjectID != pc.project.ID {
				return invalid("unknown environment")
			}
			mine, err := getGrant(ctx, tx, e.ID, e2e.PrincipalUser, c.user.ID)
			if err != nil || mine.SealedKey == nil {
				return errorf(http.StatusForbidden, api.CodeForbidden, "you can only share environments you have access to (%s)", e.Slug)
			}
			k, hasKey := keys[e.ID]
			delete(keys, e.ID)
			g := &grantRow{EnvironmentID: e.ID, PrincipalType: e2e.PrincipalInvite, PrincipalID: req.ID, KeyVersion: e.KeyVersion}
			if e.Protected {
				// Protected environments are never handed out by invite
				// code alone; an admin approves after comparing fingerprints.
				if hasKey {
					return invalid("%s is protected; its key is granted by approval, not in the invite", e.Slug)
				}
			} else {
				if !hasKey || k.PrincipalType != e2e.PrincipalInvite || k.PrincipalID != req.ID || k.KeyVersion != e.KeyVersion || len(k.SealedKey) != sealedKeySize {
					return errorf(http.StatusConflict, api.CodeStale, "the key for %s is missing or out of date; try again", e.Slug)
				}
				g.SealedKey = k.SealedKey
			}
			grants = append(grants, g)
		}
		if len(keys) > 0 {
			return invalid("keys given for environments that are not in the invite")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO invites (id, project_id, provider, handle, user_id, role, public_key, auth_hash,
			member_expires_at, expires_at, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			req.ID, pc.project.ID, req.Provider, req.Handle, userID, req.Role, req.PublicKey, req.AuthHash,
			formatTimePtr(memberExp), storage.FormatTime(now.Add(ttl)), c.user.Handle, storage.FormatTime(now)); err != nil {
			return err
		}
		for _, g := range grants {
			if err := putGrant(ctx, tx, g, now); err != nil {
				return err
			}
		}
		iv, err := getInvite(ctx, tx, req.ID)
		if err != nil {
			return err
		}
		if out, err = s.inviteAPI(ctx, tx, iv, false); err != nil {
			return err
		}
		return s.audit(ctx, tx, c, pc.project.ID, "invite.create", "", req.Handle+" as "+req.Role)
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, out)
	return nil
}

func (s *Server) listInvites(w http.ResponseWriter, r *http.Request, c *caller) error {
	ctx := r.Context()
	pc, err := s.loadProject(ctx, s.db, r, c)
	if err != nil {
		return err
	}
	if err := pc.atLeast(api.RoleAdmin); err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM invites WHERE project_id = ? AND expires_at > ? ORDER BY created_at`,
		pc.project.ID, storage.FormatTime(s.now()))
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
	out := []api.Invite{}
	for _, id := range ids {
		iv, err := getInvite(ctx, s.db, id)
		if err != nil {
			return err
		}
		ai, err := s.inviteAPI(ctx, s.db, iv, false)
		if err != nil {
			return err
		}
		out = append(out, ai)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) revokeInvite(w http.ResponseWriter, r *http.Request, c *caller) error {
	ctx := r.Context()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		pc, err := s.loadProject(ctx, tx, r, c)
		if err != nil {
			return err
		}
		if err := pc.atLeast(api.RoleAdmin); err != nil {
			return err
		}
		iv, err := getInvite(ctx, tx, r.PathValue("id"))
		if err != nil || iv.ProjectID != pc.project.ID {
			return errNotFound
		}
		if err := revokeGrants(ctx, tx, e2e.PrincipalInvite, iv.ID, "", false); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM invites WHERE id = ?`, iv.ID); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, c, pc.project.ID, "invite.revoke", "", iv.Handle); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}

var errInviteUnusable = errorf(http.StatusNotFound, api.CodeNotFound,
	"invite not found: it may have expired, been used or revoked, or be meant for a different account")

// checkInvite loads an invite for the caller. Every failure looks the same
// so the endpoint cannot be used to probe invites.
func (s *Server) checkInvite(ctx context.Context, q storage.Querier, r *http.Request, c *caller, authKey []byte) (*inviteRow, error) {
	if err := s.limit(r, "invite", 10, 10); err != nil {
		return nil, err
	}
	iv, err := getInvite(ctx, q, r.PathValue("id"))
	if errors.Is(err, storage.ErrNotFound) {
		return nil, errInviteUnusable
	}
	if err != nil {
		return nil, err
	}
	matches := iv.Provider == c.user.Provider && strings.EqualFold(iv.Handle, c.user.Handle)
	if iv.UserID.Valid {
		matches = iv.UserID.String == c.user.ID
	}
	if !matches || !s.now().Before(iv.ExpiresAt) || !e2e.CheckAuth(authKey, iv.AuthHash) {
		return nil, errInviteUnusable
	}
	return iv, nil
}

func (s *Server) openInvite(w http.ResponseWriter, r *http.Request, c *caller) error {
	var req api.InviteAuthRequest
	if err := decode(r, maxBodyBytes, &req); err != nil {
		return err
	}
	ctx := r.Context()
	iv, err := s.checkInvite(ctx, s.db, r, c, req.AuthKey)
	if err != nil {
		return err
	}
	out, err := s.inviteAPI(ctx, s.db, iv, true)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) acceptInvite(w http.ResponseWriter, r *http.Request, c *caller) error {
	if err := requireKey(c); err != nil {
		return err
	}
	var req api.AcceptInviteRequest
	if err := decode(r, maxBodyBytes, &req); err != nil {
		return err
	}
	ctx := r.Context()
	var out api.Project
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		iv, err := s.checkInvite(ctx, tx, r, c, req.AuthKey)
		if err != nil {
			return err
		}
		now := s.now()
		existing, err := getMember(ctx, tx, iv.ProjectID, c.user.ID, now)
		switch {
		case err == nil && existing.Role == api.RoleOwner:
			return invalid("you own this project")
		case err == nil:
			_, err = tx.ExecContext(ctx, `UPDATE members SET role = ?, expires_at = ? WHERE project_id = ? AND user_id = ?`,
				iv.Role, formatTimePtr(iv.MemberExpiresAt), iv.ProjectID, c.user.ID)
		case errors.Is(err, storage.ErrNotFound):
			_, err = tx.ExecContext(ctx, `INSERT INTO members (project_id, user_id, role, expires_at, added_by, created_at)
				VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (project_id, user_id) DO UPDATE SET role = excluded.role,
				expires_at = excluded.expires_at, added_by = excluded.added_by, created_at = excluded.created_at`,
				iv.ProjectID, c.user.ID, iv.Role, formatTimePtr(iv.MemberExpiresAt), iv.CreatedBy, storage.FormatTime(now))
		}
		if err != nil {
			return err
		}
		keys := map[string]api.SealedKey{}
		for _, k := range req.Keys {
			keys[k.EnvironmentID] = k
		}
		grants, err := grantsFor(ctx, tx, e2e.PrincipalInvite, iv.ID)
		if err != nil {
			return err
		}
		var slugs []string
		for envID, g := range grants {
			e, err := getEnvByID(ctx, tx, envID)
			if err != nil {
				return err
			}
			slugs = append(slugs, e.Slug)
			mine, err := getGrant(ctx, tx, envID, e2e.PrincipalUser, c.user.ID)
			if err != nil && !errors.Is(err, storage.ErrNotFound) {
				return err
			}
			if g.SealedKey == nil {
				if mine == nil {
					if err := putGrant(ctx, tx, &grantRow{EnvironmentID: envID, PrincipalType: e2e.PrincipalUser, PrincipalID: c.user.ID,
						KeyVersion: e.KeyVersion}, now); err != nil {
						return err
					}
				}
				continue
			}
			k, ok := keys[envID]
			if !ok || k.PrincipalType != e2e.PrincipalUser || k.PrincipalID != c.user.ID || k.KeyVersion != e.KeyVersion || len(k.SealedKey) != sealedKeySize {
				return errorf(http.StatusConflict, api.CodeStale, "the key for %s is missing or out of date; try again", e.Slug)
			}
			if err := putGrant(ctx, tx, &grantRow{EnvironmentID: envID, PrincipalType: e2e.PrincipalUser, PrincipalID: c.user.ID,
				KeyVersion: e.KeyVersion, SealedKey: k.SealedKey}, now); err != nil {
				return err
			}
		}
		if err := revokeGrants(ctx, tx, e2e.PrincipalInvite, iv.ID, "", false); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM invites WHERE id = ?`, iv.ID); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, c, iv.ProjectID, "invite.accept", strings.Join(slugs, ","), "as "+iv.Role); err != nil {
			return err
		}
		p, err := getProjectByID(ctx, tx, iv.ProjectID)
		if err != nil {
			return err
		}
		out, err = s.projectAPI(ctx, tx, p, iv.Role, e2e.PrincipalUser, c.user.ID)
		out.MemberExpiresAt = iv.MemberExpiresAt
		return err
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request, c *caller) error {
	var req api.CreateTokenRequest
	if err := decode(r, maxBodyBytes, &req); err != nil {
		return err
	}
	if !e2e.ValidID(req.ID) {
		return invalid("token id must be 32 lowercase hex characters")
	}
	name, err := domain.CleanName("token name", req.Name, 64)
	if err != nil {
		return invalid("%v", err)
	}
	if _, err := e2e.ParsePublicKey(req.PublicKey); err != nil || len(req.AuthHash) != 32 {
		return invalid("public_key or auth_hash is malformed")
	}
	now := s.now()
	exp := req.ExpiresAt.UTC().Truncate(time.Millisecond)
	if !exp.After(now) || exp.After(now.Add(MaxTokenTTL)) {
		return invalid("token expiry must be in the future and at most a year away")
	}
	if len(req.Keys) == 0 || len(req.Keys) > 50 {
		return invalid("choose at least one environment")
	}
	ctx := r.Context()
	var out api.Token
	err = s.db.WithTx(ctx, func(tx *sql.Tx) error {
		pc, err := s.loadProject(ctx, tx, r, c)
		if err != nil {
			return err
		}
		if err := pc.atLeast(api.RoleAdmin); err != nil {
			return err
		}
		out = api.Token{ID: req.ID, Name: name, CreatedBy: c.user.Handle, CreatedAt: now, ExpiresAt: exp}
		seen := map[string]bool{}
		var grants []*grantRow
		for _, k := range req.Keys {
			e, err := getEnvByID(ctx, tx, k.EnvironmentID)
			if err != nil || e.ProjectID != pc.project.ID || seen[e.ID] {
				return invalid("unknown or duplicate environment")
			}
			seen[e.ID] = true
			mine, err := getGrant(ctx, tx, e.ID, e2e.PrincipalUser, c.user.ID)
			if err != nil || mine.SealedKey == nil {
				return errorf(http.StatusForbidden, api.CodeForbidden, "you can only share environments you have access to (%s)", e.Slug)
			}
			if k.PrincipalType != e2e.PrincipalToken || k.PrincipalID != req.ID || k.KeyVersion != e.KeyVersion || len(k.SealedKey) != sealedKeySize {
				return errorf(http.StatusConflict, api.CodeStale, "the key for %s is out of date; try again", e.Slug)
			}
			grants = append(grants, &grantRow{EnvironmentID: e.ID, PrincipalType: e2e.PrincipalToken, PrincipalID: req.ID,
				KeyVersion: e.KeyVersion, SealedKey: k.SealedKey})
			out.Environments = append(out.Environments, e.Slug)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO tokens (id, project_id, name, public_key, auth_hash, expires_at, created_by, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, req.ID, pc.project.ID, name, req.PublicKey, req.AuthHash,
			storage.FormatTime(exp), c.user.Handle, storage.FormatTime(now)); err != nil {
			return err
		}
		for _, g := range grants {
			if err := putGrant(ctx, tx, g, now); err != nil {
				return err
			}
		}
		return s.audit(ctx, tx, c, pc.project.ID, "token.create", strings.Join(out.Environments, ","), name)
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, out)
	return nil
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request, c *caller) error {
	ctx := r.Context()
	pc, err := s.loadProject(ctx, s.db, r, c)
	if err != nil {
		return err
	}
	if err := pc.atLeast(api.RoleAdmin); err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM tokens WHERE project_id = ? AND expires_at > ? ORDER BY created_at`,
		pc.project.ID, storage.FormatTime(s.now()))
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
	envs, err := listEnvs(ctx, s.db, pc.project.ID)
	if err != nil {
		return err
	}
	out := []api.Token{}
	for _, id := range ids {
		t, err := getToken(ctx, s.db, id)
		if err != nil {
			return err
		}
		grants, err := grantsFor(ctx, s.db, e2e.PrincipalToken, id)
		if err != nil {
			return err
		}
		at := api.Token{ID: t.ID, Name: t.Name, CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
			LastUsedAt: t.LastUsedAt, Environments: []string{}}
		for _, e := range envs {
			if grants[e.ID] != nil {
				at.Environments = append(at.Environments, e.Slug)
			}
		}
		out = append(out, at)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request, c *caller) error {
	ctx := r.Context()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		pc, err := s.loadProject(ctx, tx, r, c)
		if err != nil {
			return err
		}
		if err := pc.atLeast(api.RoleAdmin); err != nil {
			return err
		}
		t, err := getToken(ctx, tx, r.PathValue("id"))
		if err != nil || t.ProjectID != pc.project.ID {
			return errNotFound
		}
		if err := revokeGrants(ctx, tx, e2e.PrincipalToken, t.ID, "", true); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM tokens WHERE id = ?`, t.ID); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, c, pc.project.ID, "token.revoke", "", t.Name); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}

func (s *Server) tokenState(w http.ResponseWriter, r *http.Request, c *caller) error {
	ctx := r.Context()
	var out api.TokenState
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		p, err := getProjectByID(ctx, tx, c.token.ProjectID)
		if err != nil {
			return err
		}
		if out.Project, err = s.projectAPI(ctx, tx, p, api.RoleViewer, e2e.PrincipalToken, c.token.ID); err != nil {
			return err
		}
		grants, err := grantsFor(ctx, tx, e2e.PrincipalToken, c.token.ID)
		if err != nil {
			return err
		}
		out.Environments = []api.EnvironmentState{}
		for _, ae := range out.Project.Environments {
			e, err := getEnvByID(ctx, tx, ae.ID)
			if err != nil {
				return err
			}
			st := envState(p.ID, e, grants[e.ID])
			out.Environments = append(out.Environments, st)
			if st.Content != nil {
				if err := s.audit(ctx, tx, c, p.ID, "token.pull", e.Slug, revisionDetail(e.Revision)); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request, c *caller) error {
	ctx := r.Context()
	pc, err := s.loadProject(ctx, s.db, r, c)
	if err != nil {
		return err
	}
	if err := pc.atLeast(api.RoleAdmin); err != nil {
		return err
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT created_at, actor, action, environment, detail, ip FROM audit
		WHERE project_id = ? ORDER BY id DESC LIMIT ?`, pc.project.ID, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	out := []api.AuditEvent{}
	for rows.Next() {
		var ev api.AuditEvent
		var at string
		if err := rows.Scan(&at, &ev.Actor, &ev.Action, &ev.Environment, &ev.Detail, &ev.IP); err != nil {
			return err
		}
		ev.Time = storage.ParseTime(at)
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}
