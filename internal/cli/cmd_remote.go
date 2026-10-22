package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/enigma-137/ven/internal/e2e"
	"github.com/enigma-137/ven/internal/envfile"
	"github.com/enigma-137/ven/internal/remote/api"
	"github.com/enigma-137/ven/internal/remote/client"
	"github.com/enigma-137/ven/internal/vault"
	"github.com/spf13/cobra"
)

func (c *cli) remoteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Manage hosted projects on a VEN server",
		Long: `Manage hosted projects on the VEN server you logged in to with ven login.

Hosted projects are end-to-end encrypted: values are encrypted on your
machine and the server only stores ciphertext. Each environment has its own
key, so access to development never implies access to production.`,
	}
	cmd.AddCommand(c.remoteListCommand(), c.remoteCreateCommand(), c.remotePublishCommand(),
		c.remoteEnvsCommand(), c.remoteRotateCommand(), c.remoteDeleteCommand())
	return cmd
}

func (c *cli) remoteListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List hosted projects you are a member of",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := c.remote()
			if err != nil {
				return err
			}
			list, err := cl.Projects(cmd.Context())
			if err != nil {
				return remoteErr(err)
			}
			if len(list) == 0 {
				c.infof("No hosted projects yet. Create one with ven remote create or ven remote publish.")
				return nil
			}
			var rows [][]string
			for _, p := range list {
				var envs []string
				for _, e := range p.Environments {
					label := e.Slug
					switch {
					case e.Access == api.AccessPending:
						label += " (pending approval)"
					case e.Access == "":
						label += " (no access)"
					case e.NeedsRotation:
						label += " (rotation due)"
					}
					envs = append(envs, label)
				}
				exp := "never"
				if p.MemberExpiresAt != nil {
					exp = p.MemberExpiresAt.Local().Format("2006-01-02")
				}
				rows = append(rows, []string{p.Ref(), p.Role, exp, strings.Join(envs, ", ")})
			}
			table(c.env.Out, []string{"PROJECT", "ROLE", "ACCESS UNTIL", "ENVIRONMENTS"}, rows)
			return nil
		},
	}
}

// newEnvRequest creates an environment key sealed to the user's own key.
func newEnvRequest(me *api.Me, projectID, name string, protected *bool) (api.CreateEnvironmentRequest, []byte, error) {
	id, err := e2e.NewID()
	if err != nil {
		return api.CreateEnvironmentRequest{}, nil, err
	}
	key, err := e2e.NewEnvKey()
	if err != nil {
		return api.CreateEnvironmentRequest{}, nil, err
	}
	sealed, err := e2e.SealEnvKey(me.PublicKey, key, projectID, id, 1, e2e.PrincipalUser, me.ID)
	if err != nil {
		return api.CreateEnvironmentRequest{}, nil, err
	}
	return api.CreateEnvironmentRequest{ID: id, Name: name, Protected: protected, SealedKey: sealed}, key, nil
}

// requireAccountKey returns the user, failing if no account key exists yet.
// Creating projects and environments only needs the public key.
func (c *cli) requireAccountKey(ctx context.Context, cl *client.Client) (*api.Me, error) {
	me, err := cl.Me(ctx)
	if err != nil {
		return nil, remoteErr(err)
	}
	if me.PublicKey == nil {
		return nil, withCode(ExitAuth, fmt.Errorf("your account has no key yet: run ven login to set one up"))
	}
	return me, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c *cli) createHosted(ctx context.Context, cl *client.Client, me *api.Me, name string, envNames []string, protect map[string]bool) (*api.Project, map[string][]byte, error) {
	pid, err := e2e.NewID()
	if err != nil {
		return nil, nil, err
	}
	req := api.CreateProjectRequest{ID: pid, Name: name}
	keys := map[string][]byte{}
	for _, n := range envNames {
		var prot *bool
		if protect[strings.ToLower(n)] {
			t := true
			prot = &t
		}
		er, key, err := newEnvRequest(me, pid, n, prot)
		if err != nil {
			return nil, nil, err
		}
		req.Environments = append(req.Environments, er)
		keys[er.ID] = key
	}
	p, err := cl.CreateProject(ctx, req)
	if err != nil {
		for _, k := range keys {
			vault.Wipe(k)
		}
		return nil, nil, remoteErr(err)
	}
	return p, keys, nil
}

func (c *cli) remoteCreateCommand() *cobra.Command {
	var envs, protect string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a hosted project",
		Long: `Create a hosted project owned by you. Environments named production, prod or
live are protected: sharing them always needs an approval with a fingerprint
check. Use --protect to protect others too.`,
		Example: `  ven remote create "Billing API"
  ven remote create api --envs dev,staging,prod --protect staging`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cl, err := c.remote()
			if err != nil {
				return err
			}
			me, err := c.requireAccountKey(ctx, cl)
			if err != nil {
				return err
			}
			prot := map[string]bool{}
			for _, p := range splitList(protect) {
				prot[strings.ToLower(p)] = true
			}
			p, keys, err := c.createHosted(ctx, cl, me, args[0], splitList(envs), prot)
			if err != nil {
				return err
			}
			for _, k := range keys {
				vault.Wipe(k)
			}
			c.successf("Created %s", p.Ref())
			for _, e := range p.Environments {
				note := ""
				if e.Protected {
					note = " (protected)"
				}
				c.infof("  %s%s", e.Slug, note)
			}
			c.infof("Next: ven link %s -e <env>, then ven push", p.Ref())
			return nil
		},
	}
	cmd.Flags().StringVar(&envs, "envs", "development,staging,production", "comma-separated environments")
	cmd.Flags().StringVar(&protect, "protect", "", "comma-separated environments to protect in addition to production-like ones")
	return cmd
}

func (c *cli) remotePublishCommand() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "publish <local-project>",
		Short: "Upload a project from your local vault as a new hosted project",
		Long: `Copy a project from the local vault to the VEN server as a new hosted
project with the same environments and values. Values are decrypted with
your local master password and re-encrypted under new environment keys on
this machine; the local project is not changed.

With --password-stdin, only the local master password is read from stdin.`,
		Example: `  ven remote publish billing-api
  ven remote publish billing-api --name "Billing API (team)"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := c.requireInitialized(ctx)
			if err != nil {
				return err
			}
			lp, lenvs, err := a.Environments.List(ctx, args[0])
			if err != nil {
				return err
			}
			cl, err := c.remote()
			if err != nil {
				return err
			}
			me, err := c.requireAccountKey(ctx, cl)
			if err != nil {
				return err
			}
			k, err := c.unlock(ctx)
			if err != nil {
				return err
			}
			defer k.Destroy()
			contents := map[string][]byte{}
			var names []string
			for _, e := range lenvs {
				entries, err := a.Variables.Entries(ctx, k, e.ID)
				if err != nil {
					return err
				}
				names = append(names, e.Name)
				if len(entries) > 0 {
					contents[strings.ToLower(e.Name)] = envfile.Serialize(entries)
				}
			}
			defer func() {
				for _, b := range contents {
					clear(b)
				}
			}()
			if name == "" {
				name = lp.Name
			}
			p, keys, err := c.createHosted(ctx, cl, me, name, names, nil)
			if err != nil {
				return err
			}
			defer func() {
				for _, k := range keys {
					vault.Wipe(k)
				}
			}()
			total := 0
			for _, e := range p.Environments {
				data := contents[strings.ToLower(e.Name)]
				if data == nil {
					continue
				}
				nonce, ct, err := e2e.SealEnv(keys[e.ID], data, p.ID, e.ID, e.KeyVersion, e.Revision+1)
				if err != nil {
					return err
				}
				if _, err := cl.PutContent(ctx, p.Ref(), e.Slug, api.PutContentRequest{BaseRevision: e.Revision, KeyVersion: e.KeyVersion,
					Content: api.Content{Nonce: nonce, Ciphertext: ct}}); err != nil {
					return fmt.Errorf("upload %s: %w", e.Slug, remoteErr(err))
				}
				total++
			}
			c.successf("Published %s as %s (%d environment(s) with values)", lp.Slug, p.Ref(), total)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "name for the hosted project (default: the local project's name)")
	return cmd
}

func (c *cli) remoteEnvsCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "envs", Short: "Manage environments of a hosted project"}
	var rf remoteFlags
	var protected bool
	create := &cobra.Command{
		Use:   "create <name>",
		Short: "Add an environment (admins)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := rf.fill(); err != nil {
				return err
			}
			cl, err := c.remote()
			if err != nil {
				return err
			}
			p, err := c.resolveProject(ctx, cl, rf.project)
			if err != nil {
				return err
			}
			me, err := c.requireAccountKey(ctx, cl)
			if err != nil {
				return err
			}
			var prot *bool
			if cmd.Flags().Changed("protected") {
				prot = &protected
			}
			req, key, err := newEnvRequest(me, p.ID, args[0], prot)
			if err != nil {
				return err
			}
			vault.Wipe(key)
			e, err := cl.CreateEnvironment(ctx, p.Ref(), req)
			if err != nil {
				return remoteErr(err)
			}
			c.successf("Created environment %s in %s", e.Slug, p.Ref())
			return nil
		},
	}
	rf.register(create.Flags(), false)
	create.Flags().BoolVar(&protected, "protected", false, "require approval with a fingerprint check to share (default: true for production-like names)")
	cmd.AddCommand(create)
	return cmd
}

func (c *cli) remoteRotateCommand() *cobra.Command {
	var rf remoteFlags
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Replace an environment's encryption key",
		Long: `Generate a new key for an environment, re-encrypt its content and seal the
key again to everyone who currently has access. VEN does this automatically
after someone loses access; run it by hand if you suspect a key leaked.

Rotation protects future values. Anyone who already had access may have
copied the old values, so also rotate the secrets themselves at their source.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, env, err := c.session(ctx, &rf, true)
			if err != nil {
				return err
			}
			if !s.canWrite() {
				return withCode(ExitUsage, fmt.Errorf("rotating needs the developer role or higher"))
			}
			o, err := s.open(ctx, env.Slug)
			if err != nil {
				return err
			}
			defer o.wipe()
			n, err := c.rotate(ctx, s, o)
			if err != nil {
				return err
			}
			vault.Wipe(n.key)
			c.successf("Rotated %s/%s to key version %d", s.project.Ref(), env.Slug, n.env().KeyVersion)
			return nil
		},
	}
	rf.register(cmd.Flags(), true)
	return cmd
}

func (c *cli) remoteDeleteCommand() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "delete <owner/slug>",
		Short: "Delete a hosted project and all its environments (owner only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cl, err := c.remote()
			if err != nil {
				return err
			}
			p, err := c.resolveProject(ctx, cl, args[0])
			if err != nil {
				return err
			}
			if !yes {
				if !c.env.Term.Interactive() {
					return needInput("pass --yes to delete %s", p.Ref())
				}
				ans, err := c.env.Term.ReadLine(fmt.Sprintf("This deletes %s for every member. Type %s to confirm: ", p.Ref(), p.Slug))
				if err != nil {
					return err
				}
				if strings.TrimSpace(ans) != p.Slug {
					return ErrCancelled
				}
			}
			if err := cl.DeleteProject(ctx, p.Ref()); err != nil {
				return remoteErr(err)
			}
			c.successf("Deleted %s", p.Ref())
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation")
	return cmd
}
