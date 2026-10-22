package cli

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/enigma-137/ven/internal/e2e"
	"github.com/enigma-137/ven/internal/envfile"
	"github.com/enigma-137/ven/internal/remote/api"
	"github.com/enigma-137/ven/internal/remote/client"
	"github.com/enigma-137/ven/internal/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// linkFileName records which hosted project and environment a directory
// uses. It holds no secrets.
const linkFileName = ".ven.json"

type linkFile struct {
	Project string `json:"project"`
	Env     string `json:"env,omitempty"`
}

// findLink looks for .ven.json in the working directory and its parents.
func findLink() (*linkFile, string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, "", err
	}
	for {
		path := filepath.Join(dir, linkFileName)
		b, err := os.ReadFile(path)
		if err == nil {
			var lf linkFile
			if err := json.Unmarshal(b, &lf); err != nil {
				return nil, "", fmt.Errorf("read %s: %w", path, err)
			}
			return &lf, path, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, "", nil
		}
		dir = parent
	}
}

type remoteFlags struct {
	project string
	env     string
}

func (f *remoteFlags) register(fs *pflag.FlagSet, withEnv bool) {
	fs.StringVarP(&f.project, "project", "p", "", "hosted project as owner/slug or slug (default: from .ven.json)")
	if withEnv {
		fs.StringVarP(&f.env, "env", "e", "", "environment slug (default: from .ven.json)")
	}
}

// fill applies .ven.json defaults to unset flags.
func (f *remoteFlags) fill() error {
	if f.project != "" && f.env != "" {
		return nil
	}
	lf, _, err := findLink()
	if err != nil || lf == nil {
		return err
	}
	if f.project == "" {
		f.project = lf.Project
		if f.env == "" {
			f.env = lf.Env
		}
	}
	return nil
}

// resolveProject finds a hosted project by owner/slug or by a slug that is
// unique among the user's projects.
func (c *cli) resolveProject(ctx context.Context, cl *client.Client, ref string) (*api.Project, error) {
	if ref == "" {
		return nil, needInput("pass --project owner/slug or run ven link in this directory")
	}
	if strings.Contains(ref, "/") {
		p, err := cl.Project(ctx, ref)
		return p, remoteErr(err)
	}
	list, err := cl.Projects(ctx)
	if err != nil {
		return nil, remoteErr(err)
	}
	var matches []api.Project
	for _, p := range list {
		if strings.EqualFold(p.Slug, ref) {
			matches = append(matches, p)
		}
	}
	switch len(matches) {
	case 0:
		return nil, withCode(ExitNotFound, fmt.Errorf("no hosted project %q (see ven remote list)", ref))
	case 1:
		return &matches[0], nil
	}
	var refs []string
	for _, p := range matches {
		refs = append(refs, p.Ref())
	}
	return nil, usageErr("%q matches several projects; use one of: %s", ref, strings.Join(refs, ", "))
}

func pickEnv(p *api.Project, ref string) (*api.Environment, error) {
	if ref == "" {
		if len(p.Environments) == 1 {
			return &p.Environments[0], nil
		}
		var slugs []string
		for _, e := range p.Environments {
			slugs = append(slugs, e.Slug)
		}
		return nil, needInput("pass --env (one of: %s) or run ven link", strings.Join(slugs, ", "))
	}
	for i := range p.Environments {
		if strings.EqualFold(p.Environments[i].Slug, ref) {
			return &p.Environments[i], nil
		}
	}
	return nil, withCode(ExitNotFound, fmt.Errorf("environment %q not found in %s (or you have no access to it)", ref, p.Ref()))
}

// envSession is an authenticated principal that can decrypt environments:
// a logged-in user with an unlocked account key, or a service token.
type envSession struct {
	cl      *client.Client
	project *api.Project
	priv    *ecdh.PrivateKey
	ptype   string
	pid     string
	tokens  *api.TokenState // service token mode
}

func (s *envSession) canWrite() bool {
	return s.ptype == e2e.PrincipalUser && api.RoleRank(s.project.Role) >= api.RoleRank(api.RoleDeveloper)
}

// openedEnv is a decrypted environment.
type openedEnv struct {
	state   *api.EnvironmentState
	key     []byte
	plain   []byte
	entries []envfile.Entry
}

func (o *openedEnv) wipe() {
	vault.Wipe(o.key)
	vault.Wipe(o.plain)
}

func (o *openedEnv) env() api.Environment { return o.state.Environment }

// session builds an envSession from $VEN_TOKEN or the saved login, and
// resolves the target environment before asking for any password.
func (c *cli) session(ctx context.Context, rf *remoteFlags, needEnv bool) (*envSession, *api.Environment, error) {
	if tok := os.Getenv(EnvToken); tok != "" {
		return c.tokenSession(ctx, tok, rf.env, needEnv)
	}
	if err := rf.fill(); err != nil {
		return nil, nil, err
	}
	cl, err := c.remote()
	if err != nil {
		return nil, nil, err
	}
	p, err := c.resolveProject(ctx, cl, rf.project)
	if err != nil {
		return nil, nil, err
	}
	var env *api.Environment
	if needEnv {
		if env, err = pickEnv(p, rf.env); err != nil {
			return nil, nil, err
		}
		if env.Access == api.AccessPending {
			return nil, nil, withCode(ExitAuth, fmt.Errorf("%s is protected and your access is waiting for approval: ask an admin to run ven members approve", env.Slug))
		}
		if env.Access != api.AccessActive {
			return nil, nil, withCode(ExitAuth, fmt.Errorf("you do not have access to %s", env.Slug))
		}
	}
	me, priv, err := c.unlockAccount(ctx, cl)
	if err != nil {
		return nil, nil, err
	}
	return &envSession{cl: cl, project: p, priv: priv, ptype: e2e.PrincipalUser, pid: me.ID}, env, nil
}

func (c *cli) tokenSession(ctx context.Context, tok, envRef string, needEnv bool) (*envSession, *api.Environment, error) {
	server := os.Getenv(EnvServer)
	if server == "" {
		return nil, nil, usageErr("%s is set, so %s must name the server", EnvToken, EnvServer)
	}
	server, err := client.CheckServerURL(server)
	if err != nil {
		return nil, nil, usageErr("%v", err)
	}
	id, secret, err := e2e.ParseCredential(e2e.TokenPrefix, tok)
	if err != nil {
		return nil, nil, usageErr("%s: %v", EnvToken, err)
	}
	priv, err := secret.PrivateKey()
	if err != nil {
		return nil, nil, err
	}
	auth, err := secret.AuthKey()
	if err != nil {
		return nil, nil, err
	}
	cl := c.newClient(server)
	cl.TokenID, cl.TokenAuthKey = id, auth
	st, err := cl.TokenState(ctx)
	if err != nil {
		return nil, nil, remoteErr(err)
	}
	s := &envSession{cl: cl, project: &st.Project, priv: priv, ptype: e2e.PrincipalToken, pid: id, tokens: st}
	var env *api.Environment
	if needEnv {
		if env, err = pickEnv(&st.Project, envRef); err != nil {
			return nil, nil, err
		}
	}
	return s, env, nil
}

// open fetches and decrypts one environment.
func (s *envSession) open(ctx context.Context, envSlug string) (*openedEnv, error) {
	var st *api.EnvironmentState
	if s.tokens != nil {
		for i := range s.tokens.Environments {
			if s.tokens.Environments[i].Environment.Slug == envSlug {
				st = &s.tokens.Environments[i]
			}
		}
		if st == nil {
			return nil, withCode(ExitNotFound, fmt.Errorf("this token has no access to %s", envSlug))
		}
	} else {
		var err error
		if st, err = s.cl.Environment(ctx, s.project.Ref(), envSlug); err != nil {
			return nil, remoteErr(err)
		}
	}
	return s.decrypt(st)
}

func (s *envSession) decrypt(st *api.EnvironmentState) (*openedEnv, error) {
	e := st.Environment
	if st.SealedKey == nil {
		return nil, withCode(ExitAuth, fmt.Errorf("no key for %s was shared with you", e.Slug))
	}
	key, err := e2e.OpenEnvKey(s.priv, st.SealedKey, st.ProjectID, e.ID, e.KeyVersion, s.ptype, s.pid)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt the key for %s: %w", e.Slug, err)
	}
	o := &openedEnv{state: st, key: key}
	if st.Content == nil {
		return o, nil
	}
	if o.plain, err = e2e.OpenEnv(key, st.Content.Nonce, st.Content.Ciphertext, st.ProjectID, e.ID, e.KeyVersion, e.Revision); err != nil {
		vault.Wipe(key)
		return nil, fmt.Errorf("cannot decrypt %s: %w", e.Slug, err)
	}
	parsed := envfile.Parse(o.plain)
	if parsed.HasErrors() {
		o.wipe()
		return nil, fmt.Errorf("decrypted content of %s is not valid dotenv", e.Slug)
	}
	o.entries = parsed.Entries
	return o, nil
}

// rotate replaces the environment key, re-sealing it to every current
// recipient and re-encrypting the content.
func (c *cli) rotate(ctx context.Context, s *envSession, o *openedEnv) (*openedEnv, error) {
	e := o.env()
	ref := s.project.Ref()
	recips, err := s.cl.Recipients(ctx, ref, e.Slug)
	if err != nil {
		return nil, remoteErr(err)
	}
	newKey, err := e2e.NewEnvKey()
	if err != nil {
		return nil, err
	}
	newVersion, newRev := e.KeyVersion+1, e.Revision+1
	req := api.RotateRequest{FromKeyVersion: e.KeyVersion, BaseRevision: e.Revision}
	for _, r := range recips {
		sealed, err := e2e.SealEnvKey(r.PublicKey, newKey, o.state.ProjectID, e.ID, newVersion, r.Type, r.ID)
		if err != nil {
			return nil, fmt.Errorf("seal key for %s %s: %w", r.Type, r.Label, err)
		}
		req.Keys = append(req.Keys, api.SealedKey{EnvironmentID: e.ID, PrincipalType: r.Type, PrincipalID: r.ID, KeyVersion: newVersion, SealedKey: sealed})
	}
	if o.state.Content != nil {
		nonce, ct, err := e2e.SealEnv(newKey, o.plain, o.state.ProjectID, e.ID, newVersion, newRev)
		if err != nil {
			return nil, err
		}
		req.Content = &api.Content{Nonce: nonce, Ciphertext: ct}
	}
	updated, err := s.cl.Rotate(ctx, ref, e.Slug, req)
	if err != nil {
		vault.Wipe(newKey)
		return nil, remoteErr(err)
	}
	vault.Wipe(o.key)
	st := *o.state
	st.Environment = *updated
	st.Content = req.Content
	return &openedEnv{state: &st, key: newKey, plain: o.plain, entries: o.entries}, nil
}

// rotateIfNeeded rotates when someone lost access since the last rotation
// and the caller is allowed to.
func (c *cli) rotateIfNeeded(ctx context.Context, s *envSession, o *openedEnv) (*openedEnv, error) {
	if !o.env().NeedsRotation {
		return o, nil
	}
	if !s.canWrite() {
		c.warnf("someone lost access to %s; a developer or admin should run a pull so its key is rotated", o.env().Slug)
		return o, nil
	}
	n, err := c.rotate(ctx, s, o)
	if err != nil {
		return nil, fmt.Errorf("rotate the key for %s: %w", o.env().Slug, err)
	}
	c.successf("Rotated the key for %s because someone lost access", o.env().Slug)
	return n, nil
}

func (c *cli) pullCommand() *cobra.Command {
	var rf remoteFlags
	var out string
	var stdout, force, yes bool
	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Decrypt a hosted environment into a .env file",
		Long: `Download a hosted environment, decrypt it on this machine and write it as a
dotenv file. Asks before overwriting an existing file.

Prefer 'ven run -- <command>' where possible: it passes the variables to one
process without leaving a plaintext file on disk.

With $VEN_TOKEN and $VEN_SERVER set, pull uses that service token instead of
your login (for CI and servers).`,
		Example: `  ven pull                                  # project/env from .ven.json
  ven pull -p acme/billing-api -e staging --out .env.staging
  ven pull --stdout | some-tool`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, env, err := c.session(ctx, &rf, true)
			if err != nil {
				return err
			}
			o, err := s.open(ctx, env.Slug)
			if err != nil {
				return err
			}
			defer func() { o.wipe() }()
			if o, err = c.rotateIfNeeded(ctx, s, o); err != nil {
				return err
			}
			data := envfile.Serialize(o.entries)
			defer clear(data)
			if stdout {
				_, err := c.env.Out.Write(data)
				return err
			}
			dest, err := filepath.Abs(out)
			if err != nil {
				return err
			}
			if info, err := os.Stat(dest); err == nil {
				if info.IsDir() {
					return fmt.Errorf("%s is a directory", dest)
				}
				if !force {
					if !c.env.Term.Interactive() || yes {
						return withCode(ExitConflict, fmt.Errorf("%w: %s (use --force to overwrite)", envfile.ErrExists, dest))
					}
					ok, err := c.confirm(fmt.Sprintf("%s exists. Overwrite it?", dest), false)
					if err != nil {
						return err
					}
					if !ok {
						return ErrCancelled
					}
					force = true
				}
			}
			if err := envfile.WriteFile(dest, data, force); err != nil {
				if errors.Is(err, envfile.ErrExists) {
					return withCode(ExitConflict, err)
				}
				return err
			}
			c.successf("Wrote %d variable(s) from %s/%s to %s", len(o.entries), s.project.Ref(), env.Slug, dest)
			return nil
		},
	}
	rf.register(cmd.Flags(), true)
	cmd.Flags().StringVarP(&out, "out", "o", ".env", "destination file")
	cmd.Flags().BoolVar(&stdout, "stdout", false, "write dotenv content to stdout instead of a file")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite the destination if it exists")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "never prompt")
	return cmd
}

type pushDiff struct {
	added, changed, removed []string
}

func (d pushDiff) empty() bool { return len(d.added)+len(d.changed)+len(d.removed) == 0 }

func diffEntries(old, next []envfile.Entry) pushDiff {
	var d pushDiff
	before := map[string]string{}
	for _, e := range old {
		before[e.Key] = e.Value
	}
	after := map[string]bool{}
	for _, e := range next {
		after[e.Key] = true
		v, ok := before[e.Key]
		switch {
		case !ok:
			d.added = append(d.added, e.Key)
		case v != e.Value:
			d.changed = append(d.changed, e.Key)
		}
	}
	for _, e := range old {
		if !after[e.Key] {
			d.removed = append(d.removed, e.Key)
		}
	}
	return d
}

func (c *cli) pushCommand() *cobra.Command {
	var rf remoteFlags
	var from string
	var merge, yes bool
	cmd := &cobra.Command{
		Use:   "push",
		Short: "Encrypt a .env file and upload it to a hosted environment",
		Long: `Encrypt a dotenv file on this machine and upload it as the new content of a
hosted environment. By default the environment is made to match the file
(keys missing from the file are removed); --merge only adds and updates.

VEN shows which keys are added, changed and removed (never values) and asks
before uploading. If someone else pushed in the meantime, the push is
refused: pull, reapply your change and push again.`,
		Example: `  ven push                                  # .env → project/env from .ven.json
  ven push --from .env.staging -e staging
  ven push --merge --yes`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if os.Getenv(EnvToken) != "" {
				return usageErr("service tokens are read-only; unset %s to push as yourself", EnvToken)
			}
			src, err := readLimited(from, envfile.MaxFileSize)
			if err != nil {
				return err
			}
			parsed := envfile.Parse(src)
			clear(src)
			for _, is := range parsed.Issues {
				fmt.Fprintf(c.env.Err, "  %s line %d: %s\n", is.Severity, is.Line, is.Message)
			}
			if parsed.HasErrors() {
				return fmt.Errorf("%s has %d error(s); nothing was pushed", from, len(parsed.Errors()))
			}
			s, env, err := c.session(ctx, &rf, true)
			if err != nil {
				return err
			}
			if !s.canWrite() {
				return withCode(ExitUsage, fmt.Errorf("your role on %s is %s; pushing needs developer or higher", s.project.Ref(), s.project.Role))
			}
			o, err := s.open(ctx, env.Slug)
			if err != nil {
				return err
			}
			defer func() { o.wipe() }()
			if o, err = c.rotateIfNeeded(ctx, s, o); err != nil {
				return err
			}
			next := parsed.Entries
			if merge {
				next = mergeEntries(o.entries, parsed.Entries)
			}
			d := diffEntries(o.entries, next)
			if d.empty() {
				c.infof("%s/%s is already up to date.", s.project.Ref(), env.Slug)
				return nil
			}
			c.infof("Pushing to %s/%s:", s.project.Ref(), env.Slug)
			for _, k := range d.added {
				c.infof("  %s %s", c.color(colorGreen, "+"), k)
			}
			for _, k := range d.changed {
				c.infof("  %s %s", c.color(colorYellow, "~"), k)
			}
			for _, k := range d.removed {
				c.infof("  %s %s", c.color(colorRed, "-"), k)
			}
			if !yes {
				if !c.env.Term.Interactive() {
					return needInput("pass --yes to push without confirmation")
				}
				ok, err := c.confirm(fmt.Sprintf("Push %d added, %d changed, %d removed?", len(d.added), len(d.changed), len(d.removed)), len(d.removed) == 0)
				if err != nil {
					return err
				}
				if !ok {
					return ErrCancelled
				}
			}
			content := envfile.Serialize(next)
			defer clear(content)
			e := o.env()
			nonce, ct, err := e2e.SealEnv(o.key, content, o.state.ProjectID, e.ID, e.KeyVersion, e.Revision+1)
			if err != nil {
				return err
			}
			updated, err := s.cl.PutContent(ctx, s.project.Ref(), e.Slug, api.PutContentRequest{
				BaseRevision: e.Revision, KeyVersion: e.KeyVersion, Content: api.Content{Nonce: nonce, Ciphertext: ct}})
			if err != nil {
				return remoteErr(err)
			}
			c.successf("Pushed %s/%s (revision %d)", s.project.Ref(), e.Slug, updated.Revision)
			return nil
		},
	}
	rf.register(cmd.Flags(), true)
	cmd.Flags().StringVar(&from, "from", ".env", "dotenv file to upload")
	cmd.Flags().BoolVar(&merge, "merge", false, "only add and update keys; keep keys missing from the file")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "push without confirmation")
	return cmd
}

func mergeEntries(old, add []envfile.Entry) []envfile.Entry {
	out := slices.Clone(old)
	idx := map[string]int{}
	for i, e := range out {
		idx[e.Key] = i
	}
	for _, e := range add {
		if i, ok := idx[e.Key]; ok {
			out[i].Value = e.Value
		} else {
			idx[e.Key] = len(out)
			out = append(out, e)
		}
	}
	return out
}

func (c *cli) runCommand() *cobra.Command {
	var rf remoteFlags
	cmd := &cobra.Command{
		Use:   "run [-p project] [-e env] -- <command> [args...]",
		Short: "Run a command with a hosted environment's variables (nothing written to disk)",
		Long: `Decrypt a hosted environment and run a command with its variables added to
the environment. Variables from VEN override ones already set. Nothing is
written to disk. The command's exit code is passed through.`,
		Example: `  ven run -- npm run dev
  ven run -e staging -- ./deploy.sh
  VEN_SERVER=https://ven.example.com VEN_TOKEN=ven_st_… ven run -- ./migrate`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, env, err := c.session(ctx, &rf, true)
			if err != nil {
				return err
			}
			o, err := s.open(ctx, env.Slug)
			if err != nil {
				return err
			}
			defer func() { o.wipe() }()
			if o, err = c.rotateIfNeeded(ctx, s, o); err != nil {
				return err
			}
			environ := os.Environ()
			for _, e := range o.entries {
				environ = append(environ, e.Key+"="+e.Value)
			}
			child := exec.CommandContext(ctx, args[0], args[1:]...)
			child.Env = environ
			child.Stdin = c.env.stdinReader()
			child.Stdout = c.env.Out
			child.Stderr = c.env.Err
			if err := child.Run(); err != nil {
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					return withCode(ee.ExitCode(), quietError{err})
				}
				return err
			}
			return nil
		},
	}
	rf.register(cmd.Flags(), true)
	cmd.Flags().SetInterspersed(false)
	return cmd
}

// quietError carries an exit code without printing an error line (the
// child process already reported its own failure).
type quietError struct{ error }

func shellQuote(shell, key, value string) (string, error) {
	switch shell {
	case "posix", "sh", "bash", "zsh":
		return "export " + key + "='" + strings.ReplaceAll(value, "'", `'\''`) + "'", nil
	case "fish":
		v := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(value)
		return "set -gx " + key + " '" + v + "'", nil
	case "powershell", "pwsh":
		return "$env:" + key + " = '" + strings.ReplaceAll(value, "'", "''") + "'", nil
	}
	return "", usageErr("--shell must be posix, fish or powershell")
}

func defaultShell() string {
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	return "posix"
}

func (c *cli) envCommand() *cobra.Command {
	var rf remoteFlags
	var shell string
	cmd := &cobra.Command{
		Use:   "shellenv",
		Short: "Print shell commands that export a hosted environment",
		Long: `Print commands that set a hosted environment's variables in your current
shell. Evaluate the output; it contains plaintext values.`,
		Example: `  eval "$(ven shellenv)"                     # bash / zsh
  ven shellenv --shell fish | source          # fish
  ven shellenv | Invoke-Expression            # PowerShell`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if _, err := shellQuote(shell, "X", ""); err != nil {
				return err
			}
			s, env, err := c.session(ctx, &rf, true)
			if err != nil {
				return err
			}
			o, err := s.open(ctx, env.Slug)
			if err != nil {
				return err
			}
			defer func() { o.wipe() }()
			if o, err = c.rotateIfNeeded(ctx, s, o); err != nil {
				return err
			}
			w := bufio.NewWriter(c.env.Out)
			for _, e := range o.entries {
				line, _ := shellQuote(shell, e.Key, e.Value)
				fmt.Fprintln(w, line)
			}
			return w.Flush()
		},
	}
	rf.register(cmd.Flags(), true)
	cmd.Flags().StringVar(&shell, "shell", defaultShell(), "output syntax: posix, fish or powershell")
	return cmd
}

func writeClipboard(data []byte) error {
	var candidates [][]string
	switch runtime.GOOS {
	case "windows":
		candidates = [][]string{{"powershell", "-NoProfile", "-Command", "$input | Set-Clipboard"}, {"clip"}}
	case "darwin":
		candidates = [][]string{{"pbcopy"}}
	default:
		candidates = [][]string{{"wl-copy"}, {"xclip", "-selection", "clipboard"}, {"xsel", "--clipboard", "--input"}}
	}
	for _, cand := range candidates {
		if _, err := exec.LookPath(cand[0]); err != nil {
			continue
		}
		cmd := exec.Command(cand[0], cand[1:]...)
		cmd.Stdin = strings.NewReader(string(data))
		return cmd.Run()
	}
	return errors.New("no clipboard tool found (install wl-copy, xclip or xsel)")
}

func (c *cli) copyCommand() *cobra.Command {
	var rf remoteFlags
	cmd := &cobra.Command{
		Use:   "copy [KEY]",
		Short: "Copy a hosted environment (or one value) to the clipboard",
		Long: `Copy a whole hosted environment as KEY=value lines, or a single value, to the
clipboard. Clipboard contents are plaintext and other apps can read them;
clear the clipboard when you are done.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, env, err := c.session(ctx, &rf, true)
			if err != nil {
				return err
			}
			o, err := s.open(ctx, env.Slug)
			if err != nil {
				return err
			}
			defer func() { o.wipe() }()
			var data []byte
			what := fmt.Sprintf("%d variable(s)", len(o.entries))
			if len(args) == 1 {
				i := slices.IndexFunc(o.entries, func(e envfile.Entry) bool { return e.Key == args[0] })
				if i < 0 {
					return withCode(ExitNotFound, fmt.Errorf("%s is not set in %s", args[0], env.Slug))
				}
				data, what = []byte(o.entries[i].Value), args[0]
			} else {
				var b strings.Builder
				for _, e := range o.entries {
					b.WriteString(envfile.FormatLine(e.Key, e.Value) + "\n")
				}
				data = []byte(b.String())
			}
			defer clear(data)
			clip := writeClipboard
			if c.clipboard != nil {
				clip = c.clipboard
			}
			if err := clip(data); err != nil {
				return err
			}
			c.successf("Copied %s from %s/%s to the clipboard", what, s.project.Ref(), env.Slug)
			return nil
		},
	}
	rf.register(cmd.Flags(), true)
	return cmd
}

func (c *cli) linkCommand() *cobra.Command {
	var envRef string
	cmd := &cobra.Command{
		Use:   "link <project> [--env <environment>]",
		Short: "Link this directory to a hosted project and environment",
		Long: `Write .ven.json in the current directory so pull, push, run, shellenv and copy
work without flags. The file holds no secrets and is safe to commit. VEN
also adds .env to .gitignore when this directory has one or is a git
repository.`,
		Example: `  ven link acme/billing-api --env development
  ven link billing-api -e staging`,
		Args: cobra.ExactArgs(1),
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
			env, err := pickEnv(p, envRef)
			if err != nil {
				return err
			}
			b, _ := json.MarshalIndent(linkFile{Project: p.Ref(), Env: env.Slug}, "", "  ")
			if err := os.WriteFile(linkFileName, append(b, '\n'), 0o644); err != nil {
				return err
			}
			c.successf("Linked this directory to %s (%s)", p.Ref(), env.Slug)
			if added, err := ensureGitignore(".env"); err != nil {
				c.warnf("could not update .gitignore: %v", err)
			} else if added {
				c.infof("Added .env to .gitignore")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&envRef, "env", "e", "", "environment slug")
	return cmd
}

// ensureGitignore appends pattern to ./.gitignore if this directory has a
// .gitignore or .git and the pattern is not listed yet.
func ensureGitignore(pattern string) (bool, error) {
	_, errIgnore := os.Stat(".gitignore")
	_, errGit := os.Stat(".git")
	if errIgnore != nil && errGit != nil {
		return false, nil
	}
	b, err := os.ReadFile(".gitignore")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == pattern || strings.TrimSpace(line) == "/"+pattern {
			return false, nil
		}
	}
	prefix := ""
	if len(b) > 0 && !strings.HasSuffix(string(b), "\n") {
		prefix = "\n"
	}
	f, err := os.OpenFile(".gitignore", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false, err
	}
	defer f.Close()
	_, err = f.WriteString(prefix + pattern + "\n")
	return err == nil, err
}
