package cli

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/enigma-137/ven/internal/app"
	"github.com/enigma-137/ven/internal/e2e"
	"github.com/enigma-137/ven/internal/remote/api"
	"github.com/enigma-137/ven/internal/remote/client"
	"github.com/enigma-137/ven/internal/vault"
	"github.com/spf13/cobra"
)

// Environment variables for hosted use.
const (
	EnvServer = "VEN_SERVER" // server URL for login and service tokens
	EnvToken  = "VEN_TOKEN"  // service token (ven_st_...) for CI and servers
)

// accountPath is account.json next to the vault, so --vault and $VEN_VAULT
// also isolate the login (handy for tests and multiple identities).
func (c *cli) accountPath() (string, error) {
	vp, err := app.ResolveVaultPath(c.opts.vaultPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(vp), "account.json"), nil
}

func (c *cli) newClient(server string) *client.Client {
	cl := client.New(server)
	cl.UserAgent = "ven/" + app.Version
	if c.httpClient != nil {
		cl.HTTP = c.httpClient
	}
	return cl
}

// remote returns a client for the logged-in account.
func (c *cli) remote() (*client.Client, error) {
	path, err := c.accountPath()
	if err != nil {
		return nil, err
	}
	acc, err := client.LoadAccount(path)
	if err != nil {
		return nil, err
	}
	if acc.Server == "" || acc.Session == nil {
		return nil, withCode(ExitAuth, client.ErrNotLoggedIn)
	}
	cl := c.newClient(acc.Server)
	cl.Account, cl.AccountPath = acc, path
	return cl, nil
}

func (c *cli) sleepFor(ctx context.Context, d time.Duration) error {
	if c.sleep != nil {
		return c.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// remoteErr maps API errors onto CLI exit codes.
func remoteErr(err error) error {
	var ae *client.APIError
	if errors.As(err, &ae) {
		switch ae.Code {
		case api.CodeUnauthenticated:
			return withCode(ExitAuth, err)
		case api.CodeNotFound:
			return withCode(ExitNotFound, err)
		case api.CodeConflict, api.CodeStale, api.CodeRotationRequired:
			return withCode(ExitConflict, err)
		case api.CodeInvalid, api.CodeForbidden:
			return withCode(ExitUsage, err)
		}
	}
	if errors.Is(err, client.ErrNotLoggedIn) {
		return withCode(ExitAuth, err)
	}
	return err
}

func (c *cli) accountKDF() vault.KDFParams {
	if c.kdf != nil {
		return *c.kdf
	}
	return vault.DefaultKDF
}

// unlockAccount fetches the user's wrapped private key and opens it with
// the account password.
func (c *cli) unlockAccount(ctx context.Context, cl *client.Client) (*api.Me, *ecdh.PrivateKey, error) {
	me, err := cl.Me(ctx)
	if err != nil {
		return nil, nil, remoteErr(err)
	}
	if me.WrappedPrivateKey == nil || me.PublicKey == nil {
		return nil, nil, withCode(ExitAuth, errors.New("your account has no key yet: run ven login to set one up"))
	}
	try := func(pw []byte) (*ecdh.PrivateKey, error) {
		defer vault.Wipe(pw)
		return e2e.UnwrapPrivateKey(me.WrappedPrivateKey, pw, me.ID, me.PublicKey)
	}
	if c.opts.passwordStdin {
		pw, err := c.readStdinLine()
		if err != nil {
			return nil, nil, err
		}
		k, err := try(pw)
		if errors.Is(err, e2e.ErrIncorrectPassword) {
			err = withCode(ExitAuth, err)
		}
		return me, k, err
	}
	if !c.env.Term.Interactive() {
		return nil, nil, needInput("the account password is required: run in a terminal or pass --password-stdin")
	}
	for attempt := 1; ; attempt++ {
		pw, err := c.env.Term.ReadPassword("Account password: ")
		if err != nil {
			return nil, nil, err
		}
		k, err := try(pw)
		if errors.Is(err, e2e.ErrIncorrectPassword) {
			if attempt < 3 {
				c.warnf("Incorrect account password, try again.")
				continue
			}
			return nil, nil, withCode(ExitAuth, err)
		}
		return me, k, err
	}
}

func (c *cli) loginCommand() *cobra.Command {
	var server string
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to a VEN server with GitHub",
		Long: `Log in to a VEN server with your GitHub account.

VEN shows a short code; open the link, enter the code and approve. GitHub
only tells VEN who you are; VEN asks for no GitHub permissions.

The first time, you also choose an account password. It protects your
account key, which is what decrypts shared environments. It never leaves
this machine, and neither VEN nor GitHub can reset it.`,
		Example: `  ven login --server https://ven.example.com
  ven login                                    # same server as last time`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			path, err := c.accountPath()
			if err != nil {
				return err
			}
			acc, err := client.LoadAccount(path)
			if err != nil {
				return err
			}
			if server == "" {
				server = os.Getenv(EnvServer)
			}
			if server == "" {
				server = acc.Server
			}
			if server == "" {
				return usageErr("pass --server https://your-ven-server (or set %s)", EnvServer)
			}
			if server, err = client.CheckServerURL(server); err != nil {
				return usageErr("%v", err)
			}
			cl := c.newClient(server)
			ds, err := cl.DeviceStart(ctx, "github")
			if err != nil {
				return remoteErr(err)
			}
			c.infof("Open %s and enter the code:", ds.VerificationURI)
			c.infof("")
			c.infof("    %s", c.color(colorBold, ds.UserCode))
			c.infof("")
			if !noBrowser && c.env.Term.Interactive() {
				_ = openBrowser(ds.VerificationURI)
			}
			c.infof("Waiting for approval…")
			interval := time.Duration(ds.Interval) * time.Second
			deadline := time.Now().Add(time.Duration(ds.ExpiresIn) * time.Second)
			var sess *api.Session
			for {
				if err := c.sleepFor(ctx, interval); err != nil {
					return err
				}
				sess, err = cl.DevicePoll(ctx, "github", ds.DeviceCode)
				switch {
				case err == nil:
				case client.IsCode(err, api.CodeAuthPending):
					if ds.ExpiresIn > 0 && time.Now().After(deadline) {
						return withCode(ExitAuth, errors.New("the login code expired; run ven login again"))
					}
					continue
				case client.IsCode(err, api.CodeSlowDown):
					interval += 5 * time.Second
					continue
				default:
					return remoteErr(err)
				}
				break
			}
			acc = &client.Account{Server: server, Session: sess}
			if err := acc.Save(path); err != nil {
				return err
			}
			cl.Account, cl.AccountPath = acc, path
			c.successf("Logged in as %s on %s", sess.User.Handle, server)

			me, err := cl.Me(ctx)
			if err != nil {
				return remoteErr(err)
			}
			if me.PublicKey != nil {
				c.infof("Account key fingerprint: %s", e2e.Fingerprint(me.PublicKey))
				return nil
			}
			c.infof("")
			c.infof("Set up your account password. It encrypts your account key and cannot be")
			c.infof("reset by anyone: if you lose it you must be re-invited to every project.")
			pw, err := c.readNewPassword("Account password")
			if err != nil {
				return err
			}
			defer vault.Wipe(pw)
			priv, err := e2e.GenerateKey()
			if err != nil {
				return err
			}
			wk, err := e2e.WrapPrivateKey(priv, pw, me.ID, c.accountKDF())
			if err != nil {
				return err
			}
			if err := cl.SetKey(ctx, api.SetKeyRequest{PublicKey: priv.PublicKey().Bytes(), WrappedPrivateKey: *wk}); err != nil {
				return remoteErr(err)
			}
			c.successf("Account key created. Fingerprint: %s", e2e.Fingerprint(priv.PublicKey().Bytes()))
			return nil
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "VEN server URL (default: $VEN_SERVER or the last server used)")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "do not try to open a browser")
	return cmd
}

func (c *cli) logoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out and revoke this device's session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := c.accountPath()
			if err != nil {
				return err
			}
			acc, err := client.LoadAccount(path)
			if err != nil {
				return err
			}
			if acc.Session == nil {
				c.infof("Not logged in.")
				return nil
			}
			cl := c.newClient(acc.Server)
			cl.Account = acc
			if err := cl.Logout(cmd.Context()); err != nil {
				c.warnf("could not revoke the session on the server (%v); removing it locally", err)
			}
			acc.Session = nil
			if err := acc.Save(path); err != nil {
				return err
			}
			c.successf("Logged out")
			return nil
		},
	}
}

func (c *cli) whoamiCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the logged-in account and its key fingerprint",
		Long: `Show the logged-in account and its key fingerprint.

When someone approves your access to a protected environment, they will ask
you to read out this fingerprint so they can check that the key they are
sealing to really is yours.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := c.remote()
			if err != nil {
				return err
			}
			me, err := cl.Me(cmd.Context())
			if err != nil {
				return remoteErr(err)
			}
			fmt.Fprintf(c.env.Out, "%s (%s) on %s\n", me.Handle, me.Provider, cl.BaseURL)
			if me.PublicKey != nil {
				fmt.Fprintf(c.env.Out, "fingerprint: %s\n", e2e.Fingerprint(me.PublicKey))
			} else {
				fmt.Fprintln(c.env.Out, "no account key yet: run ven login")
			}
			return nil
		},
	}
}

// parseTTL parses durations like 30d, 12h, 45m. "never" returns 0, true.
func parseTTL(s string) (d time.Duration, never bool, err error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "never" {
		return 0, true, nil
	}
	if n, ok := strings.CutSuffix(s, "d"); ok {
		var days int
		if _, err := fmt.Sscanf(n, "%d", &days); err != nil || days <= 0 || fmt.Sprint(days) != n {
			return 0, false, fmt.Errorf("invalid duration %q (use e.g. 30d, 12h or never)", s)
		}
		return time.Duration(days) * 24 * time.Hour, false, nil
	}
	d, err = time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, false, fmt.Errorf("invalid duration %q (use e.g. 30d, 12h or never)", s)
	}
	return d, false, nil
}
