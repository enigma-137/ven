package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/enigma-137/ven/internal/e2e"
	"github.com/enigma-137/ven/internal/remote/api"
	"github.com/enigma-137/ven/internal/remote/client"
	"github.com/enigma-137/ven/internal/vault"
	"github.com/spf13/cobra"
)

// userSession resolves the project and unlocks the account key.
func (c *cli) userSession(ctx context.Context, rf *remoteFlags) (*envSession, error) {
	if err := rf.fill(); err != nil {
		return nil, err
	}
	cl, err := c.remote()
	if err != nil {
		return nil, err
	}
	p, err := c.resolveProject(ctx, cl, rf.project)
	if err != nil {
		return nil, err
	}
	me, priv, err := c.unlockAccount(ctx, cl)
	if err != nil {
		return nil, err
	}
	return &envSession{cl: cl, project: p, priv: priv, ptype: e2e.PrincipalUser, pid: me.ID}, nil
}

// selectEnvs resolves a comma-separated list (default: the linked
// environment) to environments the caller can read.
func selectEnvs(p *api.Project, list, linked string) ([]api.Environment, error) {
	names := splitList(list)
	if len(names) == 0 && linked != "" {
		names = []string{linked}
	}
	if len(names) == 0 {
		return nil, needInput("pass --env with one or more environments")
	}
	var out []api.Environment
	for _, n := range names {
		e, err := pickEnv(p, n)
		if err != nil {
			return nil, err
		}
		if e.Access != api.AccessActive {
			return nil, withCode(ExitUsage, fmt.Errorf("you can only share environments you have access to (%s)", e.Slug))
		}
		out = append(out, *e)
	}
	return out, nil
}

// rotateDue rotates every environment of the project that is flagged for
// rotation and that the caller can rotate.
func (c *cli) rotateDue(ctx context.Context, s *envSession) error {
	p, err := s.cl.Project(ctx, s.project.Ref())
	if err != nil {
		return remoteErr(err)
	}
	s.project = p
	var skipped []string
	for _, e := range p.Environments {
		if !e.NeedsRotation {
			continue
		}
		if e.Access != api.AccessActive || !s.canWrite() {
			skipped = append(skipped, e.Slug)
			continue
		}
		o, err := s.open(ctx, e.Slug)
		if err != nil {
			return err
		}
		n, err := c.rotate(ctx, s, o)
		o.wipe()
		if err != nil {
			return fmt.Errorf("rotate %s: %w", e.Slug, err)
		}
		vault.Wipe(n.key)
		c.successf("Rotated the key for %s", e.Slug)
	}
	if len(skipped) > 0 {
		c.warnf("you cannot rotate %s; it will be rotated the next time a developer or admin with access pulls it", strings.Join(skipped, ", "))
	}
	return nil
}

func (c *cli) shareCommand() *cobra.Command {
	var rf remoteFlags
	var to, envs, role, expires, inviteTTL string
	cmd := &cobra.Command{
		Use:   "share --to <github-user> --env <envs> [--role viewer|developer|admin]",
		Short: "Invite someone to a hosted project",
		Long: `Create an invite code for one GitHub account. Send the code any way you
like: it only works for that account, only once, and expires (24 hours by
default). The code carries the environment keys encrypted to a secret that
only exists inside the code, so the server cannot read them either.

Access lasts 30 days by default; extend it later with ven members renew.

Protected environments (production by default) are not unlocked by the code
alone. After the person joins, run ven members approve <user> and compare
their key fingerprint before their access is granted.`,
		Example: `  ven share --to octocat --env development,staging
  ven share -p acme/api --to octocat --env production --role developer --expires 7d`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if to == "" {
				return usageErr("--to is required")
			}
			if api.RoleRank(role) == 0 || role == api.RoleOwner {
				return usageErr("--role must be viewer, developer or admin")
			}
			req := api.CreateInviteRequest{Provider: "github", Handle: strings.TrimPrefix(to, "@"), Role: role}
			ttl, never, err := parseTTL(expires)
			if err != nil {
				return usageErr("--expires: %v", err)
			}
			if never {
				req.NoExpiry = true
			} else {
				t := time.Now().Add(ttl)
				req.MemberExpiresAt = &t
			}
			if inviteTTL != "" {
				d, never, err := parseTTL(inviteTTL)
				if err != nil || never {
					return usageErr("--invite-ttl must be a duration such as 24h")
				}
				req.TTLSeconds = int(d.Seconds())
			}
			s, err := c.userSession(ctx, &rf)
			if err != nil {
				return err
			}
			list, err := selectEnvs(s.project, envs, rf.env)
			if err != nil {
				return err
			}
			if req.ID, err = e2e.NewID(); err != nil {
				return err
			}
			secret, err := e2e.NewSecret()
			if err != nil {
				return err
			}
			defer vault.Wipe(secret)
			ipriv, err := secret.PrivateKey()
			if err != nil {
				return err
			}
			auth, err := secret.AuthKey()
			if err != nil {
				return err
			}
			req.PublicKey, req.AuthHash = ipriv.PublicKey().Bytes(), e2e.AuthHash(auth)
			var protected []string
			for _, e := range list {
				req.EnvironmentIDs = append(req.EnvironmentIDs, e.ID)
				if e.Protected {
					protected = append(protected, e.Slug)
					continue
				}
				o, err := s.open(ctx, e.Slug)
				if err != nil {
					return err
				}
				sealed, err := e2e.SealEnvKey(req.PublicKey, o.key, o.state.ProjectID, e.ID, o.env().KeyVersion, e2e.PrincipalInvite, req.ID)
				kv := o.env().KeyVersion
				o.wipe()
				if err != nil {
					return err
				}
				req.Keys = append(req.Keys, api.SealedKey{EnvironmentID: e.ID, PrincipalType: e2e.PrincipalInvite, PrincipalID: req.ID, KeyVersion: kv, SealedKey: sealed})
			}
			inv, err := s.cl.CreateInvite(ctx, s.project.Ref(), req)
			if err != nil {
				return remoteErr(err)
			}
			code := e2e.FormatCredential(e2e.InvitePrefix, req.ID, secret)
			var slugs []string
			for _, e := range inv.Environments {
				slugs = append(slugs, e.Slug)
			}
			c.successf("Invite for @%s to %s as %s (%s)", inv.Handle, inv.Project, inv.Role, strings.Join(slugs, ", "))
			c.infof("  Single use, expires %s.", inv.ExpiresAt.Local().Format("2006-01-02 15:04"))
			if inv.MemberExpiresAt != nil {
				c.infof("  Access lasts until %s.", inv.MemberExpiresAt.Local().Format("2006-01-02"))
			}
			c.infof("  They run: ven login, then ven join <code>")
			if len(protected) > 0 {
				c.infof("  %s protected: after they join, run ven members approve %s", strings.Join(protected, ", "), inv.Handle)
			}
			c.infof("")
			fmt.Fprintln(c.env.Out, code)
			return nil
		},
	}
	rf.register(cmd.Flags(), false)
	cmd.Flags().StringVar(&to, "to", "", "GitHub username to invite")
	cmd.Flags().StringVarP(&envs, "env", "e", "", "comma-separated environments (default: the linked one)")
	cmd.Flags().StringVar(&role, "role", api.RoleViewer, "viewer (pull), developer (pull and push) or admin (also share)")
	cmd.Flags().StringVar(&expires, "expires", "30d", "how long the access lasts, e.g. 30d, 90d or never")
	cmd.Flags().StringVar(&inviteTTL, "invite-ttl", "", "how long the code can be used (default 24h, max 7 days)")
	return cmd
}

func (c *cli) joinCommand() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "join <invite-code>",
		Short: "Accept an invite to a hosted project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			id, secret, err := e2e.ParseCredential(e2e.InvitePrefix, args[0])
			if err != nil {
				return usageErr("%v", err)
			}
			defer vault.Wipe(secret)
			cl, err := c.remote()
			if err != nil {
				return err
			}
			me, err := c.requireAccountKey(ctx, cl)
			if err != nil {
				return err
			}
			auth, err := secret.AuthKey()
			if err != nil {
				return err
			}
			ipriv, err := secret.PrivateKey()
			if err != nil {
				return err
			}
			inv, err := cl.OpenInvite(ctx, id, auth)
			if err != nil {
				return remoteErr(err)
			}
			c.infof("%s invited you to %s (%s) as %s.", inv.InvitedBy, inv.Project, inv.ProjectName, inv.Role)
			req := api.AcceptInviteRequest{AuthKey: auth}
			var ready, pending []string
			for _, e := range inv.Environments {
				if e.Protected {
					pending = append(pending, e.Slug)
					continue
				}
				key, err := e2e.OpenEnvKey(ipriv, e.SealedKey, inv.ProjectID, e.ID, e.KeyVersion, e2e.PrincipalInvite, inv.ID)
				if err != nil {
					return fmt.Errorf("the invite's key for %s does not decrypt: %w", e.Slug, err)
				}
				sealed, err := e2e.SealEnvKey(me.PublicKey, key, inv.ProjectID, e.ID, e.KeyVersion, e2e.PrincipalUser, me.ID)
				vault.Wipe(key)
				if err != nil {
					return err
				}
				req.Keys = append(req.Keys, api.SealedKey{EnvironmentID: e.ID, PrincipalType: e2e.PrincipalUser, PrincipalID: me.ID, KeyVersion: e.KeyVersion, SealedKey: sealed})
				ready = append(ready, e.Slug)
			}
			if !yes && c.env.Term.Interactive() {
				ok, err := c.confirm("Join?", true)
				if err != nil {
					return err
				}
				if !ok {
					return ErrCancelled
				}
			}
			p, err := cl.AcceptInvite(ctx, inv.ID, req)
			if err != nil {
				return remoteErr(err)
			}
			c.successf("Joined %s as %s", p.Ref(), p.Role)
			if len(ready) > 0 {
				c.infof("  Ready: %s. Try: ven link %s -e %s && ven pull", strings.Join(ready, ", "), p.Ref(), ready[0])
			}
			if len(pending) > 0 {
				c.infof("  Waiting for approval: %s. %s will ask you to confirm this fingerprint:", strings.Join(pending, ", "), inv.InvitedBy)
				c.infof("    %s", e2e.Fingerprint(me.PublicKey))
			}
			if p.MemberExpiresAt != nil {
				c.infof("  Your access lasts until %s.", p.MemberExpiresAt.Local().Format("2006-01-02"))
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "join without confirmation")
	return cmd
}

func (c *cli) membersCommand() *cobra.Command {
	var rf remoteFlags
	cmd := &cobra.Command{
		Use:   "members",
		Short: "List and manage members of a hosted project",
		Args:  cobra.NoArgs,
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
			list, err := cl.Members(ctx, p.Ref())
			if err != nil {
				return remoteErr(err)
			}
			var rows [][]string
			for _, m := range list {
				exp := "never"
				if m.ExpiresAt != nil {
					exp = m.ExpiresAt.Local().Format("2006-01-02")
				}
				var envs []string
				for _, e := range m.Environments {
					if e.Access == api.AccessPending {
						envs = append(envs, e.Slug+" (pending approval)")
					} else {
						envs = append(envs, e.Slug)
					}
				}
				rows = append(rows, []string{m.User.Handle, m.Role, exp, strings.Join(envs, ", ")})
			}
			table(c.env.Out, []string{"MEMBER", "ROLE", "ACCESS UNTIL", "ENVIRONMENTS"}, rows)
			return nil
		},
	}
	rf.register(cmd.PersistentFlags(), false)
	cmd.AddCommand(c.membersRemoveCommand(&rf), c.membersRenewCommand(&rf), c.membersRoleCommand(&rf), c.membersApproveCommand(&rf))
	return cmd
}

func (c *cli) membersRemoveCommand(rf *remoteFlags) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "remove <user>",
		Short: "Remove a member and rotate the keys they had",
		Long: `Remove a member. The server stops serving them immediately and VEN rotates
the keys of the environments they could read.

They may still have copies of values they pulled before. Rotate those
secrets at their source (ven audit shows what they pulled and when).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if !yes {
				if !c.env.Term.Interactive() {
					return needInput("pass --yes to remove %s", args[0])
				}
				ok, err := c.confirm(fmt.Sprintf("Remove %s?", args[0]), false)
				if err != nil {
					return err
				}
				if !ok {
					return ErrCancelled
				}
			}
			s, err := c.userSession(ctx, rf)
			if err != nil {
				return err
			}
			if err := s.cl.RemoveMember(ctx, s.project.Ref(), strings.TrimPrefix(args[0], "@")); err != nil {
				return remoteErr(err)
			}
			c.successf("Removed %s from %s", args[0], s.project.Ref())
			return c.rotateDue(ctx, s)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation")
	return cmd
}

func (c *cli) membersRenewCommand(rf *remoteFlags) *cobra.Command {
	var dur string
	cmd := &cobra.Command{
		Use:   "renew <user>",
		Short: "Extend a member's access",
		Example: `  ven members renew octocat              # 30 more days from now
  ven members renew octocat --for 90d
  ven members renew octocat --for never`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, never, err := parseTTL(dur)
			if err != nil {
				return usageErr("--for: %v", err)
			}
			req := api.UpdateMemberRequest{NoExpiry: never}
			if !never {
				t := time.Now().Add(d)
				req.ExpiresAt = &t
			}
			return c.updateMember(cmd.Context(), rf, args[0], req)
		},
	}
	cmd.Flags().StringVar(&dur, "for", "30d", "new access length from now, e.g. 30d or never")
	return cmd
}

func (c *cli) membersRoleCommand(rf *remoteFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "role <user> <viewer|developer|admin>",
		Short: "Change a member's role",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.updateMember(cmd.Context(), rf, args[0], api.UpdateMemberRequest{Role: args[1]})
		},
	}
}

func (c *cli) updateMember(ctx context.Context, rf *remoteFlags, handle string, req api.UpdateMemberRequest) error {
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
	if err := cl.UpdateMember(ctx, p.Ref(), strings.TrimPrefix(handle, "@"), req); err != nil {
		return remoteErr(err)
	}
	c.successf("Updated %s in %s", handle, p.Ref())
	return nil
}

func (c *cli) membersApproveCommand(rf *remoteFlags) *cobra.Command {
	var fingerprint string
	cmd := &cobra.Command{
		Use:   "approve <user>",
		Short: "Grant a member their pending protected environments",
		Long: `Grant a member access to the protected environments they were invited to.

VEN shows the fingerprint of the member's account key. Ask them to run
ven whoami and read theirs out (call, video, in person). Only approve if the
two match: a mismatch means the key did not come from them.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			handle := strings.TrimPrefix(args[0], "@")
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
			members, err := cl.Members(ctx, p.Ref())
			if err != nil {
				return remoteErr(err)
			}
			var target *api.Member
			for i := range members {
				if strings.EqualFold(members[i].User.Handle, handle) {
					target = &members[i]
				}
			}
			if target == nil {
				return withCode(ExitNotFound, fmt.Errorf("%s is not a member of %s", handle, p.Ref()))
			}
			var pending []string
			for _, e := range target.Environments {
				if e.Access == api.AccessPending {
					pending = append(pending, e.Slug)
				}
			}
			if len(pending) == 0 {
				c.infof("%s has no pending environments.", target.User.Handle)
				return nil
			}
			if target.User.PublicKey == nil {
				return fmt.Errorf("%s has no account key yet", target.User.Handle)
			}
			fp := e2e.Fingerprint(target.User.PublicKey)
			c.infof("Approving %s for: %s", target.User.Handle, strings.Join(pending, ", "))
			c.infof("Their key fingerprint: %s", c.color(colorBold, fp))
			switch {
			case fingerprint != "":
				if !strings.EqualFold(strings.ReplaceAll(strings.TrimSpace(fingerprint), " ", ""), fp) {
					return withCode(ExitAuth, fmt.Errorf("fingerprint mismatch: %s's key is %s; do not approve", target.User.Handle, fp))
				}
			case c.env.Term.Interactive():
				ok, err := c.confirm(fmt.Sprintf("Does %s see exactly this fingerprint in ven whoami?", target.User.Handle), false)
				if err != nil {
					return err
				}
				if !ok {
					return ErrCancelled
				}
			default:
				return needInput("pass --fingerprint with the code %s reads from ven whoami", target.User.Handle)
			}
			me, priv, err := c.unlockAccount(ctx, cl)
			if err != nil {
				return err
			}
			s := &envSession{cl: cl, project: p, priv: priv, ptype: e2e.PrincipalUser, pid: me.ID}
			var req api.ApproveRequest
			for _, slug := range pending {
				o, err := s.open(ctx, slug)
				if err != nil {
					return err
				}
				e := o.env()
				sealed, err := e2e.SealEnvKey(target.User.PublicKey, o.key, o.state.ProjectID, e.ID, e.KeyVersion, e2e.PrincipalUser, target.User.ID)
				o.wipe()
				if err != nil {
					return err
				}
				req.Keys = append(req.Keys, api.SealedKey{EnvironmentID: e.ID, PrincipalType: e2e.PrincipalUser, PrincipalID: target.User.ID, KeyVersion: e.KeyVersion, SealedKey: sealed})
			}
			if err := cl.Approve(ctx, p.Ref(), target.User.Handle, req); err != nil {
				return remoteErr(err)
			}
			c.successf("Approved %s for %s", target.User.Handle, strings.Join(pending, ", "))
			return nil
		},
	}
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "the fingerprint the member read to you (for scripts)")
	return cmd
}

func (c *cli) invitesCommand() *cobra.Command {
	var rf remoteFlags
	cmd := &cobra.Command{
		Use:   "invites",
		Short: "List pending invites of a hosted project (admins)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cl, p, err := c.projectOnly(ctx, &rf)
			if err != nil {
				return err
			}
			list, err := cl.Invites(ctx, p.Ref())
			if err != nil {
				return remoteErr(err)
			}
			var rows [][]string
			for _, iv := range list {
				var envs []string
				for _, e := range iv.Environments {
					envs = append(envs, e.Slug)
				}
				rows = append(rows, []string{iv.ID, iv.Handle, iv.Role, strings.Join(envs, ","), iv.InvitedBy, iv.ExpiresAt.Local().Format("2006-01-02 15:04")})
			}
			table(c.env.Out, []string{"ID", "FOR", "ROLE", "ENVIRONMENTS", "BY", "EXPIRES"}, rows)
			return nil
		},
	}
	rf.register(cmd.PersistentFlags(), false)
	revoke := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke an unused invite",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cl, p, err := c.projectOnly(ctx, &rf)
			if err != nil {
				return err
			}
			if err := cl.RevokeInvite(ctx, p.Ref(), args[0]); err != nil {
				return remoteErr(err)
			}
			c.successf("Revoked invite %s", args[0])
			return nil
		},
	}
	cmd.AddCommand(revoke)
	return cmd
}

func (c *cli) projectOnly(ctx context.Context, rf *remoteFlags) (*client.Client, *api.Project, error) {
	if err := rf.fill(); err != nil {
		return nil, nil, err
	}
	cl, err := c.remote()
	if err != nil {
		return nil, nil, err
	}
	p, err := c.resolveProject(ctx, cl, rf.project)
	return cl, p, err
}

func (c *cli) tokensCommand() *cobra.Command {
	var rf remoteFlags
	cmd := &cobra.Command{
		Use:   "tokens",
		Short: "List and manage read-only service tokens (admins)",
		Long: `Service tokens let CI jobs and servers read environments without a person's
login. A token is read-only, limited to the environments you choose, and
always expires. It is shown once; store it in your CI secret store.

Use it with:  VEN_SERVER=https://… VEN_TOKEN=ven_st_… ven run -- <command>`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cl, p, err := c.projectOnly(ctx, &rf)
			if err != nil {
				return err
			}
			list, err := cl.Tokens(ctx, p.Ref())
			if err != nil {
				return remoteErr(err)
			}
			var rows [][]string
			for _, t := range list {
				last := "never"
				if t.LastUsedAt != nil {
					last = ago(*t.LastUsedAt)
				}
				rows = append(rows, []string{t.ID, t.Name, strings.Join(t.Environments, ","), t.CreatedBy, t.ExpiresAt.Local().Format("2006-01-02"), last})
			}
			table(c.env.Out, []string{"ID", "NAME", "ENVIRONMENTS", "CREATED BY", "EXPIRES", "LAST USED"}, rows)
			return nil
		},
	}
	rf.register(cmd.PersistentFlags(), false)

	var envs, name, expires string
	create := &cobra.Command{
		Use:     "create --name <name> --env <envs>",
		Short:   "Create a read-only service token",
		Example: `  ven tokens create --name github-actions --env production --expires 90d`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if name == "" {
				return usageErr("--name is required")
			}
			ttl, never, err := parseTTL(expires)
			if err != nil || never {
				return usageErr("--expires must be a duration of at most 366d (tokens always expire)")
			}
			s, err := c.userSession(ctx, &rf)
			if err != nil {
				return err
			}
			list, err := selectEnvs(s.project, envs, rf.env)
			if err != nil {
				return err
			}
			req := api.CreateTokenRequest{Name: name, ExpiresAt: time.Now().Add(ttl)}
			if req.ID, err = e2e.NewID(); err != nil {
				return err
			}
			secret, err := e2e.NewSecret()
			if err != nil {
				return err
			}
			defer vault.Wipe(secret)
			tpriv, err := secret.PrivateKey()
			if err != nil {
				return err
			}
			auth, err := secret.AuthKey()
			if err != nil {
				return err
			}
			req.PublicKey, req.AuthHash = tpriv.PublicKey().Bytes(), e2e.AuthHash(auth)
			for _, e := range list {
				o, err := s.open(ctx, e.Slug)
				if err != nil {
					return err
				}
				kv := o.env().KeyVersion
				sealed, err := e2e.SealEnvKey(req.PublicKey, o.key, o.state.ProjectID, e.ID, kv, e2e.PrincipalToken, req.ID)
				o.wipe()
				if err != nil {
					return err
				}
				req.Keys = append(req.Keys, api.SealedKey{EnvironmentID: e.ID, PrincipalType: e2e.PrincipalToken, PrincipalID: req.ID, KeyVersion: kv, SealedKey: sealed})
			}
			t, err := s.cl.CreateToken(ctx, s.project.Ref(), req)
			if err != nil {
				return remoteErr(err)
			}
			c.successf("Created token %q for %s (%s), expires %s", t.Name, s.project.Ref(), strings.Join(t.Environments, ", "), t.ExpiresAt.Local().Format("2006-01-02"))
			c.warnf("this token is shown once and decrypts those environments; store it as a CI secret")
			fmt.Fprintln(c.env.Out, e2e.FormatCredential(e2e.TokenPrefix, req.ID, secret))
			return nil
		},
	}
	create.Flags().StringVar(&name, "name", "", "what the token is for, e.g. github-actions")
	create.Flags().StringVarP(&envs, "env", "e", "", "comma-separated environments (default: the linked one)")
	create.Flags().StringVar(&expires, "expires", "90d", "lifetime, at most 366d")

	revoke := &cobra.Command{
		Use:   "revoke <id-or-name>",
		Short: "Revoke a service token and rotate the keys it had",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, err := c.userSession(ctx, &rf)
			if err != nil {
				return err
			}
			list, err := s.cl.Tokens(ctx, s.project.Ref())
			if err != nil {
				return remoteErr(err)
			}
			id := ""
			for _, t := range list {
				if t.ID == args[0] || t.Name == args[0] {
					if id != "" {
						return usageErr("several tokens are named %q; pass the ID", args[0])
					}
					id = t.ID
				}
			}
			if id == "" {
				return withCode(ExitNotFound, fmt.Errorf("no token %q in %s", args[0], s.project.Ref()))
			}
			if err := s.cl.RevokeToken(ctx, s.project.Ref(), id); err != nil {
				return remoteErr(err)
			}
			c.successf("Revoked token %s", args[0])
			return c.rotateDue(ctx, s)
		},
	}
	cmd.AddCommand(create, revoke)
	return cmd
}

func (c *cli) auditCommand() *cobra.Command {
	var rf remoteFlags
	var limit int
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show who pulled, pushed, shared or changed what (admins)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cl, p, err := c.projectOnly(ctx, &rf)
			if err != nil {
				return err
			}
			list, err := cl.Audit(ctx, p.Ref(), limit)
			if err != nil {
				return remoteErr(err)
			}
			var rows [][]string
			for _, ev := range list {
				rows = append(rows, []string{ev.Time.Local().Format("2006-01-02 15:04:05"), ev.Actor, ev.Action, ev.Environment, ev.Detail, ev.IP})
			}
			table(c.env.Out, []string{"TIME", "WHO", "ACTION", "ENVIRONMENT", "DETAIL", "IP"}, rows)
			return nil
		},
	}
	rf.register(cmd.Flags(), false)
	cmd.Flags().IntVar(&limit, "limit", 50, "number of events (max 1000)")
	return cmd
}
