package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/enigma-137/ven/internal/app"
	"github.com/enigma-137/ven/internal/domain"
	"github.com/enigma-137/ven/internal/envfile"
	"github.com/enigma-137/ven/internal/environments"
	"github.com/enigma-137/ven/internal/projects"
	"github.com/enigma-137/ven/internal/storage"
	"github.com/enigma-137/ven/internal/variables"
	"github.com/enigma-137/ven/internal/vault"
)

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /api/session", s.api(accessPublic, maxBodyBytes, s.getSession))
	m.HandleFunc("POST /api/session", s.api(accessPublic, maxBodyBytes, s.createSession))
	m.HandleFunc("DELETE /api/session", s.api(accessSession, maxBodyBytes, s.deleteSession))
	// The dashboard sends a heartbeat while the user is interacting, so
	// auto-lock measures user inactivity rather than API silence.
	m.HandleFunc("POST /api/session/heartbeat", s.api(accessUnlocked, maxBodyBytes, func(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
		w.WriteHeader(http.StatusNoContent)
	}))

	m.HandleFunc("POST /api/vault/init", s.api(accessSession, maxBodyBytes, s.initVault))
	m.HandleFunc("POST /api/vault/unlock", s.api(accessSession, maxBodyBytes, s.unlockVault))
	m.HandleFunc("POST /api/vault/lock", s.api(accessSession, maxBodyBytes, s.lockVault))
	m.HandleFunc("POST /api/vault/password", s.api(accessUnlocked, maxBodyBytes, s.changePassword))

	m.HandleFunc("GET /api/settings", s.api(accessUnlocked, maxBodyBytes, s.getSettings))
	m.HandleFunc("PUT /api/settings", s.api(accessUnlocked, maxBodyBytes, s.putSettings))

	m.HandleFunc("GET /api/projects", s.api(accessUnlocked, maxBodyBytes, s.listProjects))
	m.HandleFunc("POST /api/projects", s.api(accessUnlocked, maxBodyBytes, s.createProject))
	m.HandleFunc("GET /api/projects/{project}", s.api(accessUnlocked, maxBodyBytes, s.getProject))
	m.HandleFunc("PATCH /api/projects/{project}", s.api(accessUnlocked, maxBodyBytes, s.updateProject))
	m.HandleFunc("DELETE /api/projects/{project}", s.api(accessUnlocked, maxBodyBytes, s.deleteProject))

	m.HandleFunc("POST /api/projects/{project}/environments", s.api(accessUnlocked, maxBodyBytes, s.createEnvironment))
	m.HandleFunc("PATCH /api/projects/{project}/environments/{env}", s.api(accessUnlocked, maxBodyBytes, s.renameEnvironment))
	m.HandleFunc("DELETE /api/projects/{project}/environments/{env}", s.api(accessUnlocked, maxBodyBytes, s.deleteEnvironment))

	m.HandleFunc("GET /api/projects/{project}/environments/{env}/variables", s.api(accessUnlocked, maxBodyBytes, s.listVariables))
	m.HandleFunc("POST /api/projects/{project}/environments/{env}/variables", s.api(accessUnlocked, maxBodyBytes, s.createVariable))
	m.HandleFunc("GET /api/projects/{project}/environments/{env}/text-values", s.api(accessUnlocked, maxBodyBytes, s.textValues))
	m.HandleFunc("POST /api/projects/{project}/environments/{env}/export", s.api(accessUnlocked, maxBodyBytes, s.exportEnvironment))

	m.HandleFunc("POST /api/variables/{id}/reveal", s.api(accessUnlocked, maxBodyBytes, s.revealVariable))
	m.HandleFunc("PATCH /api/variables/{id}", s.api(accessUnlocked, maxBodyBytes, s.updateVariable))
	m.HandleFunc("DELETE /api/variables/{id}", s.api(accessUnlocked, maxBodyBytes, s.deleteVariable))

	m.HandleFunc("POST /api/import/preview", s.api(accessUnlocked, maxImportBytes, s.importPreview))
	m.HandleFunc("POST /api/import/commit", s.api(accessUnlocked, maxImportBytes, s.importCommit))

	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "unknown API endpoint")
	})
	m.Handle("/", s.static)
}

// ---- JSON helpers ----

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]apiError{"error": {Code: code, Message: msg}})
}

// writeServiceError maps service errors to HTTP responses. Messages from
// services never contain values.
func (s *Server) writeServiceError(w http.ResponseWriter, err error) {
	var ve *domain.ValidationError
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &ve):
		writeError(w, http.StatusBadRequest, "validation", ve.Error())
	case errors.As(err, &mbe):
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body is too large")
	case errors.Is(err, vault.ErrLocked):
		writeError(w, http.StatusUnauthorized, "locked", "the vault is locked")
	case errors.Is(err, vault.ErrNotInitialized):
		writeError(w, http.StatusConflict, "not_initialized", "the vault is not initialized")
	case errors.Is(err, vault.ErrAlreadyInitialized):
		writeError(w, http.StatusConflict, "already_initialized", "the vault is already initialized")
	case errors.Is(err, vault.ErrIncorrectPassword):
		writeError(w, http.StatusUnauthorized, "incorrect_password", "incorrect master password")
	case errors.Is(err, storage.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, storage.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", trimDriver(err))
	case errors.Is(err, variables.ErrReplaceNotConfirmed):
		writeError(w, http.StatusBadRequest, "replace_not_confirmed", err.Error())
	case errors.Is(err, variables.ErrUnresolvedConflicts):
		writeError(w, http.StatusConflict, "unresolved_conflicts", err.Error())
	case errors.Is(err, vault.ErrDecrypt):
		writeError(w, http.StatusInternalServerError, "decrypt_failed", err.Error())
	default:
		s.cfg.Logger.Printf("internal error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

// trimDriver hides raw SQLite messages behind the service's friendly prefix.
func trimDriver(err error) string {
	if msg, _, ok := strings.Cut(err.Error(), ": already exists"); ok && msg != "" {
		return msg
	}
	return "already exists"
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body is too large")
		} else {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON request body")
		}
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request", "unexpected data after JSON body")
		return false
	}
	return true
}

// ---- DTOs ----

type projectDTO struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Slug             string    `json:"slug"`
	Description      string    `json:"description"`
	EnvironmentCount int       `json:"environmentCount"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

func toProject(p projects.Project) projectDTO {
	return projectDTO{ID: p.ID, Name: p.Name, Slug: p.Slug, Description: p.Description,
		EnvironmentCount: p.EnvironmentCount, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
}

type environmentDTO struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Slug          string    `json:"slug"`
	VariableCount int       `json:"variableCount"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

func toEnv(e environments.Environment) environmentDTO {
	return environmentDTO{ID: e.ID, Name: e.Name, Slug: e.Slug, VariableCount: e.VariableCount, CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt}
}

func toEnvs(list []environments.Environment) []environmentDTO {
	out := make([]environmentDTO, 0, len(list))
	for _, e := range list {
		out = append(out, toEnv(e))
	}
	return out
}

// ---- session & vault ----

type sessionDTO struct {
	Authenticated   bool   `json:"authenticated"`
	CSRFToken       string `json:"csrfToken,omitempty"`
	Initialized     bool   `json:"initialized"`
	Unlocked        bool   `json:"unlocked"`
	AutoLockMinutes int    `json:"autoLockMinutes"`
	Version         string `json:"version"`
}

func (s *Server) sessionState(r *http.Request, sess *session) (sessionDTO, error) {
	st, err := s.cfg.App.Vault.Status(r.Context())
	if err != nil {
		return sessionDTO{}, err
	}
	d := sessionDTO{Initialized: st.Initialized, AutoLockMinutes: s.cfg.App.AutoLockMinutes(r.Context()), Version: app.Version}
	if sess != nil {
		d.Authenticated = true
		d.CSRFToken = sess.csrf
		d.Unlocked = s.isUnlocked(sess)
	}
	return d, nil
}

// getSession reports state. It does not count as activity, so polling it
// never postpones auto-lock.
func (s *Server) getSession(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	d, err := s.sessionState(r, rc.sess)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// createSession exchanges the launch token for a session cookie.
func (s *Server) createSession(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var body struct {
		LaunchToken string `json:"launchToken"`
	}
	if !decode(w, r, &body) {
		return
	}
	if rc.sess == nil {
		if wait := s.throttle.wait(s.cfg.Now()); wait > 0 {
			writeRateLimited(w, wait)
			return
		}
		if s.cfg.LaunchToken == "" || !constantTimeEqual(body.LaunchToken, s.cfg.LaunchToken) {
			s.throttle.fail(s.cfg.Now())
			writeError(w, http.StatusUnauthorized, "invalid_launch_token", "invalid or missing launch token; open the link printed by `ven ui`")
			return
		}
		rc.sess = s.newSession(w)
	}
	d, err := s.sessionState(r, rc.sess)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.endSession(w, rc.sess)
	w.WriteHeader(http.StatusNoContent)
}

func writeRateLimited(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Seconds() + 0.999)
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeError(w, http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("too many failed attempts; try again in %d seconds", secs))
}

type passwordBody struct {
	Password string `json:"password"`
}

func (s *Server) initVault(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var body passwordBody
	if !decode(w, r, &body) {
		return
	}
	pw := []byte(body.Password)
	defer vault.Wipe(pw)
	if err := vault.ValidatePassword(pw); err != nil {
		writeError(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	s.unlockMu.Lock()
	k, err := s.cfg.App.Vault.Init(r.Context(), pw)
	s.unlockMu.Unlock()
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	s.setKey(rc.sess, k)
	s.respondSession(w, r, rc.sess)
}

func (s *Server) unlockVault(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var body passwordBody
	if !decode(w, r, &body) {
		return
	}
	pw := []byte(body.Password)
	defer vault.Wipe(pw)
	s.unlockMu.Lock()
	defer s.unlockMu.Unlock()
	if wait := s.throttle.wait(s.cfg.Now()); wait > 0 {
		writeRateLimited(w, wait)
		return
	}
	k, err := s.cfg.App.Vault.Unlock(r.Context(), pw)
	if errors.Is(err, vault.ErrIncorrectPassword) {
		s.throttle.fail(s.cfg.Now())
	}
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	s.throttle.success()
	s.setKey(rc.sess, k)
	s.respondSession(w, r, rc.sess)
}

func (s *Server) respondSession(w http.ResponseWriter, r *http.Request, sess *session) {
	d, err := s.sessionState(r, sess)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) lockVault(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.lockSession(rc.sess)
	s.respondSession(w, r, rc.sess)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if !decode(w, r, &body) {
		return
	}
	cur, next := []byte(body.CurrentPassword), []byte(body.NewPassword)
	defer vault.Wipe(cur)
	defer vault.Wipe(next)
	if err := vault.ValidatePassword(next); err != nil {
		writeError(w, http.StatusBadRequest, "validation", "new password: "+err.Error())
		return
	}
	s.unlockMu.Lock()
	defer s.unlockMu.Unlock()
	if wait := s.throttle.wait(s.cfg.Now()); wait > 0 {
		writeRateLimited(w, wait)
		return
	}
	err := s.cfg.App.Vault.ChangePassword(r.Context(), cur, next)
	if errors.Is(err, vault.ErrIncorrectPassword) {
		s.throttle.fail(s.cfg.Now())
		writeError(w, http.StatusBadRequest, "incorrect_password", "the current master password is incorrect")
		return
	}
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	s.throttle.success()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	st, err := s.cfg.App.Vault.Status(ctx)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	schema, _ := s.cfg.App.DB.SchemaVersion(ctx)
	writeJSON(w, http.StatusOK, map[string]any{
		"vaultPath":       s.cfg.App.DB.Path,
		"autoLockMinutes": s.cfg.App.AutoLockMinutes(ctx),
		"version":         app.Version,
		"schemaVersion":   schema,
		"kdf": map[string]any{
			"algorithm":   "argon2id",
			"memoryKiB":   st.KDF.Memory,
			"iterations":  st.KDF.Iterations,
			"parallelism": st.KDF.Parallelism,
		},
	})
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var body struct {
		AutoLockMinutes int `json:"autoLockMinutes"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := s.cfg.App.SetAutoLockMinutes(r.Context(), body.AutoLockMinutes); err != nil {
		writeError(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	s.getSettings(w, r, rc)
}

// ---- projects & environments ----

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	list, err := s.cfg.App.Projects.List(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	out := make([]projectDTO, 0, len(list))
	for _, p := range list {
		out = append(out, toProject(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": out})
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var body struct {
		Name         string   `json:"name"`
		Description  string   `json:"description"`
		Environments []string `json:"environments"`
	}
	if !decode(w, r, &body) {
		return
	}
	p, envs, err := s.cfg.App.Projects.Create(r.Context(), projects.CreateInput{Name: body.Name, Description: body.Description, Environments: body.Environments})
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"project": toProject(p), "environments": toEnvs(envs)})
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	p, envs, err := s.cfg.App.Environments.List(r.Context(), r.PathValue("project"))
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"project": toProject(p), "environments": toEnvs(envs)})
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var body struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if !decode(w, r, &body) {
		return
	}
	p, err := s.cfg.App.Projects.Update(r.Context(), r.PathValue("project"), projects.UpdateInput{Name: body.Name, Description: body.Description})
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"project": toProject(p)})
}

type confirmBody struct {
	Confirm string `json:"confirm"`
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var body confirmBody
	if !decode(w, r, &body) {
		return
	}
	p, err := s.cfg.App.Projects.Resolve(r.Context(), r.PathValue("project"))
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	if body.Confirm != p.Slug {
		writeError(w, http.StatusBadRequest, "confirmation_required", "type the project slug to confirm deletion")
		return
	}
	if _, err := s.cfg.App.Projects.Delete(r.Context(), p.Slug); err != nil {
		s.writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	e, err := s.cfg.App.Environments.Create(r.Context(), r.PathValue("project"), body.Name)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"environment": toEnv(e)})
}

func (s *Server) renameEnvironment(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	e, err := s.cfg.App.Environments.Rename(r.Context(), r.PathValue("project"), r.PathValue("env"), body.Name)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"environment": toEnv(e)})
}

func (s *Server) deleteEnvironment(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var body confirmBody
	if !decode(w, r, &body) {
		return
	}
	_, e, err := s.cfg.App.Environments.Resolve(r.Context(), r.PathValue("project"), r.PathValue("env"))
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	if body.Confirm != e.Slug {
		writeError(w, http.StatusBadRequest, "confirmation_required", "type the environment slug to confirm deletion")
		return
	}
	if _, err := s.cfg.App.Environments.Delete(r.Context(), r.PathValue("project"), e.Slug); err != nil {
		s.writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- variables ----

func (s *Server) envFromPath(w http.ResponseWriter, r *http.Request) (projects.Project, environments.Environment, bool) {
	p, e, err := s.cfg.App.Environments.Resolve(r.Context(), r.PathValue("project"), r.PathValue("env"))
	if err != nil {
		s.writeServiceError(w, err)
		return p, e, false
	}
	return p, e, true
}

// listVariables returns metadata only — never values.
func (s *Server) listVariables(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	_, e, ok := s.envFromPath(w, r)
	if !ok {
		return
	}
	list, err := s.cfg.App.Variables.List(r.Context(), e.ID, r.URL.Query().Get("q"))
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"variables": list})
}

// textValues returns decrypted values of text-typed variables only.
func (s *Server) textValues(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	_, e, ok := s.envFromPath(w, r)
	if !ok {
		return
	}
	vals, err := s.cfg.App.Variables.TextValues(r.Context(), rc.key, e.ID)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"values": vals})
}

func (s *Server) createVariable(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	_, e, ok := s.envFromPath(w, r)
	if !ok {
		return
	}
	var body struct {
		Key         string `json:"key"`
		Value       string `json:"value"`
		Type        string `json:"type"`
		Description string `json:"description"`
	}
	if !decode(w, r, &body) {
		return
	}
	v, _, err := s.cfg.App.Variables.Set(r.Context(), rc.key, e.ID, variables.SetInput{
		Key: body.Key, Value: body.Value, Type: body.Type, Description: &body.Description, CreateOnly: true})
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"variable": v})
}

func (s *Server) revealVariable(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	v, value, err := s.cfg.App.Variables.GetByID(r.Context(), rc.key, r.PathValue("id"))
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": v.ID, "key": v.Key, "value": value})
}

func (s *Server) updateVariable(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var body struct {
		Key         *string `json:"key"`
		Value       *string `json:"value"`
		Type        *string `json:"type"`
		Description *string `json:"description"`
	}
	if !decode(w, r, &body) {
		return
	}
	v, err := s.cfg.App.Variables.Update(r.Context(), rc.key, r.PathValue("id"), variables.UpdateInput{
		Key: body.Key, Value: body.Value, Type: body.Type, Description: body.Description})
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"variable": v})
}

func (s *Server) deleteVariable(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if _, err := s.cfg.App.Variables.DeleteByID(r.Context(), r.PathValue("id")); err != nil {
		s.writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) exportEnvironment(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	p, e, ok := s.envFromPath(w, r)
	if !ok {
		return
	}
	data, n, err := s.cfg.App.Variables.Export(r.Context(), rc.key, e.ID)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"filename": ".env." + p.Slug + "." + e.Slug,
		"count":    n,
		"content":  string(data),
	})
	clear(data)
}

// ---- import ----

type importBody struct {
	Project     string                          `json:"project"`
	Environment string                          `json:"environment"`
	Content     string                          `json:"content"`
	Mode        string                          `json:"mode"`
	OnConflict  string                          `json:"onConflict"`
	Resolutions map[string]variables.Resolution `json:"resolutions"`
	Types       map[string]string               `json:"types"`
	Confirm     bool                            `json:"confirmReplace"`
	Create      bool                            `json:"createMissing"`
}

type importTarget struct {
	ProjectExists     bool   `json:"projectExists"`
	EnvironmentExists bool   `json:"environmentExists"`
	ProjectSlug       string `json:"projectSlug"`
	EnvironmentSlug   string `json:"environmentSlug"`
	environmentID     string
}

func (s *Server) resolveImportTarget(r *http.Request, body *importBody) (importTarget, error) {
	var t importTarget
	ctx := r.Context()
	p, err := s.cfg.App.Projects.Resolve(ctx, body.Project)
	switch {
	case err == nil:
		t.ProjectExists, t.ProjectSlug = true, p.Slug
	case errors.Is(err, storage.ErrNotFound):
		if _, err := domain.CleanName("project", body.Project, 100); err != nil {
			return t, err
		}
		t.ProjectSlug = domain.Slugify(body.Project)
	default:
		return t, err
	}
	if t.ProjectExists {
		e, err := environments.ResolveIn(ctx, s.cfg.App.DB, p.ID, body.Environment)
		switch {
		case err == nil:
			t.EnvironmentExists, t.EnvironmentSlug, t.environmentID = true, e.Slug, e.ID
			return t, nil
		case !errors.Is(err, storage.ErrNotFound):
			return t, err
		}
	}
	if _, err := domain.CleanName("environment", body.Environment, 64); err != nil {
		return t, err
	}
	t.EnvironmentSlug = domain.Slugify(body.Environment)
	return t, nil
}

func parseImport(w http.ResponseWriter, body *importBody) (*envfile.Result, bool) {
	if len(body.Content) > envfile.MaxFileSize {
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", fmt.Sprintf("import content is larger than %d bytes", envfile.MaxFileSize))
		return nil, false
	}
	return envfile.Parse([]byte(body.Content)), true
}

func issuesOrEmpty(is []envfile.Issue) []envfile.Issue {
	if is == nil {
		return []envfile.Issue{}
	}
	return is
}

func (s *Server) importPreview(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var body importBody
	if !decode(w, r, &body) {
		return
	}
	mode, err := variables.ParseMode(body.Mode)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	res, ok := parseImport(w, &body)
	if !ok {
		return
	}
	t, err := s.resolveImportTarget(r, &body)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	resp := map[string]any{"issues": issuesOrEmpty(res.Issues), "target": t, "variableCount": len(res.Entries)}
	if !res.HasErrors() {
		plan, err := s.cfg.App.Variables.PlanImport(r.Context(), rc.key, t.environmentID, res.Entries, mode)
		if err != nil {
			s.writeServiceError(w, err)
			return
		}
		resp["plan"] = plan
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) importCommit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	var body importBody
	if !decode(w, r, &body) {
		return
	}
	mode, err := variables.ParseMode(body.Mode)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	res, ok := parseImport(w, &body)
	if !ok {
		return
	}
	if res.HasErrors() {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":  apiError{Code: "parse_errors", Message: "the input has errors; nothing was imported"},
			"issues": res.Errors(),
		})
		return
	}
	var onConflict variables.Resolution
	switch body.OnConflict {
	case "":
	case string(variables.Overwrite), string(variables.Keep):
		onConflict = variables.Resolution(body.OnConflict)
	default:
		writeError(w, http.StatusBadRequest, "validation", "onConflict must be overwrite or keep")
		return
	}
	for key, rv := range body.Resolutions {
		if rv != variables.Overwrite && rv != variables.Keep {
			writeError(w, http.StatusBadRequest, "validation", "resolution for "+key+" must be overwrite or keep")
			return
		}
	}
	t, err := s.resolveImportTarget(r, &body)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	if (!t.ProjectExists || !t.EnvironmentExists) && !body.Create {
		writeError(w, http.StatusBadRequest, "target_missing", "the target project or environment does not exist; confirm creating it")
		return
	}
	opts := variables.ImportOptions{Mode: mode, OnConflict: onConflict, Resolutions: body.Resolutions, Types: body.Types, ConfirmReplace: body.Confirm}
	if mode == variables.ModeReplace && !body.Confirm {
		s.writeServiceError(w, variables.ErrReplaceNotConfirmed)
		return
	}

	// Create the missing target, remembering how to undo it on failure.
	undo := func() {}
	if !t.ProjectExists {
		p, envs, err := s.cfg.App.Projects.Create(ctx, projects.CreateInput{Name: body.Project, Environments: []string{body.Environment}})
		if err != nil {
			s.writeServiceError(w, err)
			return
		}
		t.environmentID, t.ProjectSlug, t.EnvironmentSlug = envs[0].ID, p.Slug, envs[0].Slug
		undo = func() { _, _ = s.cfg.App.Projects.Delete(context.Background(), p.Slug) }
	} else if !t.EnvironmentExists {
		e, err := s.cfg.App.Environments.Create(ctx, t.ProjectSlug, body.Environment)
		if err != nil {
			s.writeServiceError(w, err)
			return
		}
		t.environmentID, t.EnvironmentSlug = e.ID, e.Slug
		undo = func() { _, _ = s.cfg.App.Environments.Delete(context.Background(), t.ProjectSlug, e.Slug) }
	}

	result, err := s.cfg.App.Variables.ApplyImport(ctx, rc.key, t.environmentID, res.Entries, opts)
	if err != nil {
		undo()
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": result, "projectSlug": t.ProjectSlug, "environmentSlug": t.EnvironmentSlug})
}
