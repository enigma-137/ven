package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/enigma-137/ven/internal/remote/api"
)

// identity is a verified provider account.
type identity struct {
	Provider string
	UserID   string
	Handle   string
	Name     string
}

// provider runs an OAuth device authorization flow (RFC 8628). The server
// talks to the provider itself, so provider tokens never reach clients and
// only tokens issued to VEN's own OAuth app can log anyone in.
type provider interface {
	start(ctx context.Context) (*api.DeviceStart, error)
	// poll returns the identity once the user has authorized, or an
	// *httpError with CodeAuthPending, CodeSlowDown, CodeExpired or CodeDenied.
	poll(ctx context.Context, deviceCode string) (*identity, error)
}

type gitHub struct {
	clientID string
	baseURL  string
	apiURL   string
	client   *http.Client
}

func newGitHub(cfg Config) *gitHub {
	g := &gitHub{clientID: cfg.GitHubClientID, baseURL: cfg.GitHubURL, apiURL: cfg.GitHubAPIURL, client: cfg.HTTPClient}
	if g.baseURL == "" {
		g.baseURL = "https://github.com"
	}
	if g.apiURL == "" {
		g.apiURL = "https://api.github.com"
	}
	return g
}

func (g *gitHub) postForm(ctx context.Context, path string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("github: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github: %s returned %d", path, resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

func (g *gitHub) start(ctx context.Context) (*api.DeviceStart, error) {
	var out struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
		Error           string `json:"error"`
	}
	// No scope: VEN only needs the public profile to learn who you are.
	if err := g.postForm(ctx, "/login/device/code", url.Values{"client_id": {g.clientID}}, &out); err != nil {
		return nil, err
	}
	if out.Error != "" || out.DeviceCode == "" {
		return nil, fmt.Errorf("github: device flow unavailable (%s); is device flow enabled for the OAuth app?", out.Error)
	}
	return &api.DeviceStart{DeviceCode: out.DeviceCode, UserCode: out.UserCode, VerificationURI: out.VerificationURI,
		Interval: out.Interval, ExpiresIn: out.ExpiresIn}, nil
}

func (g *gitHub) poll(ctx context.Context, deviceCode string) (*identity, error) {
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Interval    int    `json:"interval"`
	}
	err := g.postForm(ctx, "/login/oauth/access_token", url.Values{
		"client_id":   {g.clientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}, &tok)
	if err != nil {
		return nil, err
	}
	switch tok.Error {
	case "":
	case "authorization_pending":
		return nil, errorf(http.StatusBadRequest, api.CodeAuthPending, "waiting for you to authorize in the browser")
	case "slow_down":
		return nil, errorf(http.StatusBadRequest, api.CodeSlowDown, "polling too fast")
	case "expired_token", "incorrect_device_code", "bad_verification_code":
		return nil, errorf(http.StatusBadRequest, api.CodeExpired, "the login code expired; run ven login again")
	case "access_denied":
		return nil, errorf(http.StatusForbidden, api.CodeDenied, "the login was denied in the browser")
	default:
		return nil, fmt.Errorf("github: token exchange failed: %s", tok.Error)
	}
	if tok.AccessToken == "" {
		return nil, errors.New("github: no access token returned")
	}
	// The GitHub token is used for this one call and then dropped.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.apiURL+"/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: /user returned %d", resp.StatusCode)
	}
	var u struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&u); err != nil {
		return nil, fmt.Errorf("github: decode user: %w", err)
	}
	if u.ID == 0 || u.Login == "" {
		return nil, errors.New("github: incomplete user profile")
	}
	return &identity{Provider: "github", UserID: strconv.FormatInt(u.ID, 10), Handle: u.Login, Name: u.Name}, nil
}
