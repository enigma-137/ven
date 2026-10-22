package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/enigma-137/ven/internal/e2e"
	"github.com/enigma-137/ven/internal/remote/api"
	"github.com/enigma-137/ven/internal/storage"
)

const (
	accessPrefix  = "ven_at_"
	refreshPrefix = "ven_rt_"
)

// caller is the authenticated principal of a request.
type caller struct {
	user  *userRow  // set for user sessions
	token *tokenRow // set for service tokens
	ip    string
}

// actor names the caller in the audit log.
func (c *caller) actor() string {
	if c.user != nil {
		return c.user.Handle
	}
	if c.token != nil {
		return "token:" + c.token.Name
	}
	return "anonymous"
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, c *caller) error

// public wraps an unauthenticated handler.
func (s *Server) public(h handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		if err := h(w, r, &caller{ip: s.clientIP(r)}); err != nil {
			s.writeErr(w, err)
		}
	}
}

// authed wraps a handler that needs a user session.
func (s *Server) authed(limit int64, h handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		c := &caller{ip: s.clientIP(r)}
		u, err := s.authenticateUser(r)
		if err != nil {
			s.writeErr(w, err)
			return
		}
		c.user = u
		if err := h(w, r, c); err != nil {
			s.writeErr(w, err)
		}
	}
}

// tokenAuthed wraps a handler for service tokens.
func (s *Server) tokenAuthed(h handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		c := &caller{ip: s.clientIP(r)}
		if err := s.limit(r, "token", 60, 60); err != nil {
			s.writeErr(w, err)
			return
		}
		t, err := s.authenticateToken(r)
		if err != nil {
			s.writeErr(w, err)
			return
		}
		c.token = t
		if err := h(w, r, c); err != nil {
			s.writeErr(w, err)
		}
	}
}

var (
	errUnauthenticated = errorf(http.StatusUnauthorized, api.CodeUnauthenticated, "not logged in or session expired; run ven login")
	errReplay          = errors.New("refresh token replayed")
)

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if v, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func hashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

func newOpaqueToken(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) authenticateUser(r *http.Request) (*userRow, error) {
	tok := bearer(r)
	if !strings.HasPrefix(tok, accessPrefix) {
		return nil, errUnauthenticated
	}
	ctx := r.Context()
	now := s.now()
	var userID, expires string
	err := s.db.QueryRowContext(ctx, `SELECT user_id, access_expires_at FROM sessions WHERE access_hash = ?`,
		hashToken(tok)).Scan(&userID, &expires)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !now.Before(storage.ParseTime(expires))) {
		return nil, errUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	return getUser(ctx, s.db, userID)
}

func (s *Server) authenticateToken(r *http.Request) (*tokenRow, error) {
	v, ok := strings.CutPrefix(r.Header.Get("Authorization"), api.TokenAuthScheme+" ")
	if !ok {
		return nil, errUnauthenticated
	}
	id, enc, ok := strings.Cut(strings.TrimSpace(v), ".")
	auth, err := base64.RawURLEncoding.DecodeString(enc)
	if !ok || !e2e.ValidID(id) || err != nil {
		return nil, errUnauthenticated
	}
	ctx := r.Context()
	t, err := getToken(ctx, s.db, id)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, errUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	if !e2e.CheckAuth(auth, t.AuthHash) || !s.now().Before(t.ExpiresAt) {
		return nil, errUnauthenticated
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE tokens SET last_used_at = ? WHERE id = ?`, storage.FormatTime(s.now()), id)
	return t, nil
}

func (s *Server) provider(name string) (provider, error) {
	if name == "" {
		name = "github"
	}
	p, ok := s.providers[name]
	if !ok {
		return nil, invalid("unsupported login provider %q", name)
	}
	return p, nil
}

func (s *Server) deviceStart(w http.ResponseWriter, r *http.Request, c *caller) error {
	if err := s.limit(r, "device-start", 10, 10); err != nil {
		return err
	}
	var req api.DeviceStartRequest
	if err := decode(r, maxBodyBytes, &req); err != nil {
		return err
	}
	p, err := s.provider(req.Provider)
	if err != nil {
		return err
	}
	ds, err := p.start(r.Context())
	if err != nil {
		return errorf(http.StatusBadGateway, api.CodeInternal, "%v", err)
	}
	writeJSON(w, http.StatusOK, ds)
	return nil
}

func (s *Server) devicePoll(w http.ResponseWriter, r *http.Request, c *caller) error {
	if err := s.limit(r, "device-poll", 30, 30); err != nil {
		return err
	}
	var req api.DevicePollRequest
	if err := decode(r, maxBodyBytes, &req); err != nil {
		return err
	}
	if req.DeviceCode == "" || len(req.DeviceCode) > 256 {
		return invalid("device_code is required")
	}
	p, err := s.provider(req.Provider)
	if err != nil {
		return err
	}
	id, err := p.poll(r.Context(), req.DeviceCode)
	if err != nil {
		var he *httpError
		if errors.As(err, &he) {
			return err
		}
		return errorf(http.StatusBadGateway, api.CodeInternal, "%v", err)
	}
	u, err := s.upsertUser(r.Context(), id)
	if err != nil {
		return err
	}
	sess, err := s.newSession(r.Context(), u, r.UserAgent())
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, sess)
	return nil
}

// upsertUser finds or creates the VEN user for a provider identity and
// keeps the handle in sync with the provider.
func (s *Server) upsertUser(ctx context.Context, id *identity) (*userRow, error) {
	now := storage.FormatTime(s.now())
	var userID string
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		// A handle can move between provider accounts (renames). The
		// stale holder gets a placeholder handle until they log in again.
		if _, err := tx.ExecContext(ctx, `UPDATE users SET handle = handle || '~' || substr(id, 1, 8), updated_at = ?
			WHERE handle = ? AND NOT (provider = ? AND provider_user_id = ?)`, now, id.Handle, id.Provider, id.UserID); err != nil {
			return err
		}
		err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE provider = ? AND provider_user_id = ?`, id.Provider, id.UserID).Scan(&userID)
		if errors.Is(err, sql.ErrNoRows) {
			userID = storage.NewID()
			_, err = tx.ExecContext(ctx, `INSERT INTO users (id, provider, provider_user_id, handle, name, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)`, userID, id.Provider, id.UserID, id.Handle, id.Name, now, now)
			return err
		}
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE users SET handle = ?, name = ?, updated_at = ? WHERE id = ?`, id.Handle, id.Name, now, userID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return getUser(ctx, s.db, userID)
}

func (s *Server) newSession(ctx context.Context, u *userRow, userAgent string) (*api.Session, error) {
	now := s.now()
	sess := &api.Session{
		AccessToken:      newOpaqueToken(accessPrefix),
		AccessExpiresAt:  now.Add(AccessTokenTTL),
		RefreshToken:     newOpaqueToken(refreshPrefix),
		RefreshExpiresAt: now.Add(RefreshTokenTTL),
		User:             u.api(),
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (id, user_id, access_hash, access_expires_at, refresh_hash,
		refresh_expires_at, user_agent, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		storage.NewID(), u.ID, hashToken(sess.AccessToken), storage.FormatTime(sess.AccessExpiresAt),
		hashToken(sess.RefreshToken), storage.FormatTime(sess.RefreshExpiresAt), truncateString(userAgent, 200),
		storage.FormatTime(now), storage.FormatTime(now))
	return sess, err
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request, c *caller) error {
	if err := s.limit(r, "refresh", 30, 30); err != nil {
		return err
	}
	var req api.RefreshRequest
	if err := decode(r, maxBodyBytes, &req); err != nil {
		return err
	}
	if !strings.HasPrefix(req.RefreshToken, refreshPrefix) {
		return errUnauthenticated
	}
	ctx := r.Context()
	h := hashToken(req.RefreshToken)
	now := s.now()
	var out *api.Session
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var id, userID, expires string
		err := tx.QueryRowContext(ctx, `SELECT id, user_id, refresh_expires_at FROM sessions WHERE refresh_hash = ?`, h).Scan(&id, &userID, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return errReplay
		}
		if err != nil {
			return err
		}
		if !now.Before(storage.ParseTime(expires)) {
			_, _ = tx.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
			return errUnauthenticated
		}
		u, err := getUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		out = &api.Session{
			AccessToken:      newOpaqueToken(accessPrefix),
			AccessExpiresAt:  now.Add(AccessTokenTTL),
			RefreshToken:     newOpaqueToken(refreshPrefix),
			RefreshExpiresAt: now.Add(RefreshTokenTTL),
			User:             u.api(),
		}
		_, err = tx.ExecContext(ctx, `UPDATE sessions SET access_hash = ?, access_expires_at = ?, refresh_hash = ?,
			prev_refresh_hash = ?, refresh_expires_at = ?, last_used_at = ? WHERE id = ?`,
			hashToken(out.AccessToken), storage.FormatTime(out.AccessExpiresAt), hashToken(out.RefreshToken), h,
			storage.FormatTime(out.RefreshExpiresAt), storage.FormatTime(now), id)
		return err
	})
	if errors.Is(err, errReplay) {
		// A refresh token that was already rotated is being replayed, so
		// someone copied it: end that session on every device.
		if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE prev_refresh_hash = ?`, h); err != nil {
			return err
		}
		return errUnauthenticated
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, c *caller) error {
	_, err := s.db.ExecContext(r.Context(), `DELETE FROM sessions WHERE access_hash = ?`, hashToken(bearer(r)))
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) getMe(w http.ResponseWriter, r *http.Request, c *caller) error {
	me := api.Me{User: c.user.api()}
	if c.user.WrappedKey != "" {
		var wk e2e.WrappedPrivateKey
		if err := json.Unmarshal([]byte(c.user.WrappedKey), &wk); err != nil {
			return err
		}
		me.WrappedPrivateKey = &wk
	}
	writeJSON(w, http.StatusOK, me)
	return nil
}

func (s *Server) setKey(w http.ResponseWriter, r *http.Request, c *caller) error {
	var req api.SetKeyRequest
	if err := decode(r, maxBodyBytes, &req); err != nil {
		return err
	}
	if _, err := e2e.ParsePublicKey(req.PublicKey); err != nil {
		return invalid("public_key: %v", err)
	}
	wk := req.WrappedPrivateKey
	if wk.Version != e2e.FormatVersion || len(wk.Nonce) != 12 || len(wk.Ciphertext) == 0 || len(wk.Salt) < 16 {
		return invalid("wrapped_private_key is malformed")
	}
	if err := wk.Params().Validate(); err != nil {
		return invalid("wrapped_private_key: %v", err)
	}
	blob, err := json.Marshal(wk)
	if err != nil {
		return err
	}
	if req.Replace {
		return s.replaceKey(w, r, c, req.PublicKey, string(blob))
	}
	// Set once unless Replace is asked for explicitly: a silent swap would
	// cut the user off from every environment sealed to the old key.
	res, err := s.db.ExecContext(r.Context(), `UPDATE users SET public_key = ?, wrapped_private_key = ?, updated_at = ?
		WHERE id = ? AND public_key IS NULL`, req.PublicKey, string(blob), storage.FormatTime(s.now()), c.user.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var existing []byte
		_ = s.db.QueryRowContext(r.Context(), `SELECT public_key FROM users WHERE id = ?`, c.user.ID).Scan(&existing)
		if bytes.Equal(existing, req.PublicKey) {
			w.WriteHeader(http.StatusNoContent)
			return nil
		}
		return errorf(http.StatusConflict, api.CodeConflict, "this account already has a key")
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// replaceKey installs a new account key and deletes every grant sealed to
// the old one, active or pending. It never grants access: a stolen session
// gains nothing by it, and protected environments still need an approval
// that shows the new fingerprint. Each affected project's audit log records it.
func (s *Server) replaceKey(w http.ResponseWriter, r *http.Request, c *caller, pub []byte, wrapped string) error {
	ctx := r.Context()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT project_id FROM members WHERE user_id = ?`, c.user.ID)
		if err != nil {
			return err
		}
		var projects []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			projects = append(projects, id)
		}
		rows.Close()
		// Rotate too: the old key may be the reason for the reset (stolen laptop).
		if err := revokeGrants(ctx, tx, e2e.PrincipalUser, c.user.ID, "", true); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET public_key = ?, wrapped_private_key = ?, updated_at = ? WHERE id = ?`,
			pub, wrapped, storage.FormatTime(s.now()), c.user.ID); err != nil {
			return err
		}
		for _, p := range projects {
			if err := s.audit(ctx, tx, c, p, "member.key_reset", "", "new fingerprint "+e2e.Fingerprint(pub)); err != nil {
				return err
			}
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
