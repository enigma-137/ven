// Package client is the CLI's HTTP client for a VEN server, plus the local
// file that remembers the logged-in account.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/enigma-137/ven/internal/remote/api"
)

// APIError is a non-2xx response from the server.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string { return e.Message }

// IsCode reports whether err is an APIError with the given code.
func IsCode(err error, code string) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == code
}

// ErrNotLoggedIn means there is no saved session.
var ErrNotLoggedIn = errors.New("not logged in: run ven login")

// CheckServerURL normalizes a server URL and requires HTTPS, except for
// loopback addresses used in development.
func CheckServerURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("invalid server URL %q (expected https://host)", raw)
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("the server URL must use https (plain http is only allowed for localhost)")
		}
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid server URL %q", raw)
	}
	return u.String(), nil
}

// Account is the saved login (account.json, 0600).
type Account struct {
	Server  string       `json:"server"`
	Session *api.Session `json:"session,omitempty"`
}

// LoadAccount reads the account file; a missing file is an empty account.
func LoadAccount(path string) (*Account, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Account{}, nil
	}
	if err != nil {
		return nil, err
	}
	var a Account
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return &a, nil
}

// Save writes the account file atomically with 0600 permissions.
func (a *Account) Save(path string) error {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".account-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, os.ErrInvalid) {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Client talks to one server.
type Client struct {
	BaseURL string
	HTTP    *http.Client

	// Account and AccountPath, when set, provide the session and receive
	// refreshed tokens.
	Account     *Account
	AccountPath string

	// Token, when set, authenticates as a service token instead.
	TokenID      string
	TokenAuthKey []byte

	UserAgent string
	Now       func() time.Time
}

// New returns a client for baseURL.
func New(baseURL string) *Client {
	return &Client{BaseURL: baseURL, HTTP: &http.Client{Timeout: 30 * time.Second}, Now: time.Now}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any, auth bool) error {
	if auth && c.TokenID == "" {
		if err := c.ensureFresh(ctx); err != nil {
			return err
		}
	}
	err := c.send(ctx, method, path, in, out, auth)
	if auth && c.TokenID == "" && IsCode(err, api.CodeUnauthenticated) && c.Account != nil && c.Account.Session != nil {
		// The access token may have been revoked or expired early; one refresh attempt.
		if rerr := c.refresh(ctx); rerr != nil {
			return err
		}
		return c.send(ctx, method, path, in, out, auth)
	}
	return err
}

func (c *Client) send(ctx context.Context, method, path string, in, out any, auth bool) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+api.Version+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if auth {
		switch {
		case c.TokenID != "":
			req.Header.Set("Authorization", api.TokenAuthScheme+" "+c.TokenID+"."+base64.RawURLEncoding.EncodeToString(c.TokenAuthKey))
		case c.Account != nil && c.Account.Session != nil:
			req.Header.Set("Authorization", "Bearer "+c.Account.Session.AccessToken)
		default:
			return ErrNotLoggedIn
		}
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the VEN server at %s: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var ae api.Error
		if json.Unmarshal(data, &ae) != nil || ae.Code == "" {
			return &APIError{Status: resp.StatusCode, Code: api.CodeInternal, Message: fmt.Sprintf("server returned %s", resp.Status)}
		}
		return &APIError{Status: resp.StatusCode, Code: ae.Code, Message: ae.Message}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *Client) ensureFresh(ctx context.Context) error {
	if c.Account == nil || c.Account.Session == nil {
		return ErrNotLoggedIn
	}
	if c.Now().Add(time.Minute).Before(c.Account.Session.AccessExpiresAt) {
		return nil
	}
	return c.refresh(ctx)
}

func (c *Client) refresh(ctx context.Context) error {
	s := c.Account.Session
	if !c.Now().Before(s.RefreshExpiresAt) {
		return ErrNotLoggedIn
	}
	var out api.Session
	if err := c.send(ctx, http.MethodPost, "/auth/refresh", api.RefreshRequest{RefreshToken: s.RefreshToken}, &out, false); err != nil {
		if IsCode(err, api.CodeUnauthenticated) {
			return ErrNotLoggedIn
		}
		return err
	}
	c.Account.Session = &out
	if c.AccountPath != "" {
		return c.Account.Save(c.AccountPath)
	}
	return nil
}

func esc(parts ...string) string {
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return "/" + strings.Join(parts, "/")
}

func projectPath(ref string, rest ...string) string {
	owner, slug, _ := strings.Cut(ref, "/")
	return esc(append([]string{"projects", owner, slug}, rest...)...)
}

// DeviceStart begins a provider login.
func (c *Client) DeviceStart(ctx context.Context, provider string) (*api.DeviceStart, error) {
	var out api.DeviceStart
	return &out, c.do(ctx, http.MethodPost, "/auth/device", api.DeviceStartRequest{Provider: provider}, &out, false)
}

// DevicePoll checks a pending login.
func (c *Client) DevicePoll(ctx context.Context, provider, deviceCode string) (*api.Session, error) {
	var out api.Session
	return &out, c.do(ctx, http.MethodPost, "/auth/device/poll", api.DevicePollRequest{Provider: provider, DeviceCode: deviceCode}, &out, false)
}

// Logout revokes the current session.
func (c *Client) Logout(ctx context.Context) error {
	return c.send(ctx, http.MethodPost, "/auth/logout", nil, nil, true)
}

// Me returns the logged-in user.
func (c *Client) Me(ctx context.Context) (*api.Me, error) {
	var out api.Me
	return &out, c.do(ctx, http.MethodGet, "/me", nil, &out, true)
}

// SetKey registers the account key pair.
func (c *Client) SetKey(ctx context.Context, req api.SetKeyRequest) error {
	return c.do(ctx, http.MethodPut, "/me/key", req, nil, true)
}

// Projects lists the user's projects.
func (c *Client) Projects(ctx context.Context) ([]api.Project, error) {
	var out []api.Project
	return out, c.do(ctx, http.MethodGet, "/projects", nil, &out, true)
}

// CreateProject creates a project.
func (c *Client) CreateProject(ctx context.Context, req api.CreateProjectRequest) (*api.Project, error) {
	var out api.Project
	return &out, c.do(ctx, http.MethodPost, "/projects", req, &out, true)
}

// Project returns one project (ref is owner/slug).
func (c *Client) Project(ctx context.Context, ref string) (*api.Project, error) {
	var out api.Project
	return &out, c.do(ctx, http.MethodGet, projectPath(ref), nil, &out, true)
}

// DeleteProject deletes a project (owner only).
func (c *Client) DeleteProject(ctx context.Context, ref string) error {
	return c.do(ctx, http.MethodDelete, projectPath(ref), nil, nil, true)
}

// CreateEnvironment adds an environment.
func (c *Client) CreateEnvironment(ctx context.Context, ref string, req api.CreateEnvironmentRequest) (*api.Environment, error) {
	var out api.Environment
	return &out, c.do(ctx, http.MethodPost, projectPath(ref, "environments"), req, &out, true)
}

// Environment returns the encrypted state of an environment.
func (c *Client) Environment(ctx context.Context, ref, env string) (*api.EnvironmentState, error) {
	var out api.EnvironmentState
	return &out, c.do(ctx, http.MethodGet, projectPath(ref, "environments", env), nil, &out, true)
}

// PutContent uploads new encrypted content.
func (c *Client) PutContent(ctx context.Context, ref, env string, req api.PutContentRequest) (*api.Environment, error) {
	var out api.Environment
	return &out, c.do(ctx, http.MethodPut, projectPath(ref, "environments", env, "content"), req, &out, true)
}

// Recipients lists the principals holding an environment key.
func (c *Client) Recipients(ctx context.Context, ref, env string) ([]api.Recipient, error) {
	var out []api.Recipient
	return out, c.do(ctx, http.MethodGet, projectPath(ref, "environments", env, "recipients"), nil, &out, true)
}

// Rotate replaces an environment key.
func (c *Client) Rotate(ctx context.Context, ref, env string, req api.RotateRequest) (*api.Environment, error) {
	var out api.Environment
	return &out, c.do(ctx, http.MethodPost, projectPath(ref, "environments", env, "rotate"), req, &out, true)
}

// Members lists project members.
func (c *Client) Members(ctx context.Context, ref string) ([]api.Member, error) {
	var out []api.Member
	return out, c.do(ctx, http.MethodGet, projectPath(ref, "members"), nil, &out, true)
}

// UpdateMember changes a member's role or expiry.
func (c *Client) UpdateMember(ctx context.Context, ref, handle string, req api.UpdateMemberRequest) error {
	return c.do(ctx, http.MethodPatch, projectPath(ref, "members", handle), req, nil, true)
}

// RemoveMember removes a member.
func (c *Client) RemoveMember(ctx context.Context, ref, handle string) error {
	return c.do(ctx, http.MethodDelete, projectPath(ref, "members", handle), nil, nil, true)
}

// Approve grants pending protected environments.
func (c *Client) Approve(ctx context.Context, ref, handle string, req api.ApproveRequest) error {
	return c.do(ctx, http.MethodPost, projectPath(ref, "members", handle, "approve"), req, nil, true)
}

// CreateInvite creates an invite.
func (c *Client) CreateInvite(ctx context.Context, ref string, req api.CreateInviteRequest) (*api.Invite, error) {
	var out api.Invite
	return &out, c.do(ctx, http.MethodPost, projectPath(ref, "invites"), req, &out, true)
}

// Invites lists pending invites.
func (c *Client) Invites(ctx context.Context, ref string) ([]api.Invite, error) {
	var out []api.Invite
	return out, c.do(ctx, http.MethodGet, projectPath(ref, "invites"), nil, &out, true)
}

// RevokeInvite deletes an invite.
func (c *Client) RevokeInvite(ctx context.Context, ref, id string) error {
	return c.do(ctx, http.MethodDelete, projectPath(ref, "invites", id), nil, nil, true)
}

// OpenInvite fetches an invite addressed to the logged-in user.
func (c *Client) OpenInvite(ctx context.Context, id string, authKey []byte) (*api.Invite, error) {
	var out api.Invite
	return &out, c.do(ctx, http.MethodPost, esc("invites", id, "open"), api.InviteAuthRequest{AuthKey: authKey}, &out, true)
}

// AcceptInvite accepts an invite.
func (c *Client) AcceptInvite(ctx context.Context, id string, req api.AcceptInviteRequest) (*api.Project, error) {
	var out api.Project
	return &out, c.do(ctx, http.MethodPost, esc("invites", id, "accept"), req, &out, true)
}

// CreateToken creates a service token.
func (c *Client) CreateToken(ctx context.Context, ref string, req api.CreateTokenRequest) (*api.Token, error) {
	var out api.Token
	return &out, c.do(ctx, http.MethodPost, projectPath(ref, "tokens"), req, &out, true)
}

// Tokens lists service tokens.
func (c *Client) Tokens(ctx context.Context, ref string) ([]api.Token, error) {
	var out []api.Token
	return out, c.do(ctx, http.MethodGet, projectPath(ref, "tokens"), nil, &out, true)
}

// RevokeToken deletes a service token.
func (c *Client) RevokeToken(ctx context.Context, ref, id string) error {
	return c.do(ctx, http.MethodDelete, projectPath(ref, "tokens", id), nil, nil, true)
}

// TokenState returns what the configured service token can read.
func (c *Client) TokenState(ctx context.Context) (*api.TokenState, error) {
	var out api.TokenState
	return &out, c.do(ctx, http.MethodGet, "/token", nil, &out, true)
}

// Audit returns recent audit events.
func (c *Client) Audit(ctx context.Context, ref string, limit int) ([]api.AuditEvent, error) {
	var out []api.AuditEvent
	return out, c.do(ctx, http.MethodGet, projectPath(ref, "audit")+fmt.Sprintf("?limit=%d", limit), nil, &out, true)
}
