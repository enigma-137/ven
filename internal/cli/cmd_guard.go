package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/enigma-137/ven/internal/app"
	"github.com/enigma-137/ven/internal/e2e"
	"github.com/enigma-137/ven/internal/envfile"
	"github.com/enigma-137/ven/internal/guard"
	"github.com/enigma-137/ven/internal/remote/api"
	"github.com/enigma-137/ven/internal/storage"
	"github.com/enigma-137/ven/internal/variables"
	"github.com/enigma-137/ven/internal/vault"
	"github.com/spf13/cobra"
)

// hookMarker identifies a pre-commit hook written by ven guard install.
const hookMarker = "# Installed by `ven guard install`."

func (c *cli) guardPath() (string, error) {
	vp, err := app.ResolveVaultPath(c.opts.vaultPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(vp), "guard.json"), nil
}

// guardRemember updates the fingerprints for one source. It is called
// whenever values are decrypted anyway and never fails the command.
func (c *cli) guardRemember(source string, values []guard.Value) {
	path, err := c.guardPath()
	if err == nil {
		var ix *guard.Index
		if ix, err = guard.Load(path); err == nil {
			ix.Replace(source, values)
			err = ix.Save()
		}
	}
	if err != nil {
		c.warnf("could not update the ven guard index: %v", err)
	}
}

// secretValues picks the entries guard should remember: secret-typed ones
// (by stored type, or by key name when no type is known).
func secretValues(entries []envfile.Entry, types map[string]string) []guard.Value {
	var out []guard.Value
	for _, e := range entries {
		typ, ok := types[e.Key]
		if !ok {
			typ, _ = variables.Classify(e.Key)
		}
		if typ == variables.TypeSecret {
			out = append(out, guard.Value{Name: e.Key, Value: e.Value})
		}
	}
	return out
}

// rememberLocalEnv indexes one environment of the local vault.
func (c *cli) rememberLocalEnv(ctx context.Context, a *app.App, k *vault.Key, envID string) {
	env, err := storage.GetEnvironmentByID(ctx, a.DB, envID)
	if err != nil {
		return
	}
	p, err := storage.GetProjectByID(ctx, a.DB, env.ProjectID)
	if err != nil {
		return
	}
	vars, err := a.Variables.List(ctx, envID, "")
	if err != nil {
		return
	}
	types := map[string]string{}
	for _, v := range vars {
		types[v.Key] = v.Type
	}
	entries, err := a.Variables.Entries(ctx, k, envID)
	if err != nil {
		return
	}
	c.guardRemember("local:"+p.Slug+"/"+env.Slug, secretValues(entries, types))
}

func hostedSource(projectRef, env string) string { return "hosted:" + projectRef + "/" + env }

func (c *cli) guardCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "guard",
		Short: "Stop .env files and stored secrets from being committed to Git",
		Long: `ven guard catches secrets on their way into Git: .env files, and any secret
value you keep in VEN, wherever it was pasted (a config file, a test, a README).

  ven guard install      add a pre-commit hook to this repository
  ven guard scan         check a folder, the staged changes or past commits
  ven guard index        refresh what guard knows (needs your password)
  ven guard uninstall    remove the hook

Guard never needs your password at commit time. VEN keeps a local list of
salted fingerprints of your secret values (never the values themselves) and
refreshes it whenever it decrypts values anyway: pull, push, run, import,
set, export and ven guard index. Only values typed secret and at least 8
characters long are remembered.`,
	}
	cmd.AddCommand(c.guardInstallCommand(), c.guardUninstallCommand(), c.guardScanCommand(), c.guardIndexCommand(), c.guardStatusCommand())
	return cmd
}

func gitOutput(args ...string) (string, error) {
	var out, errb bytes.Buffer
	cmd := exec.Command("git", args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", errors.New("git is not installed or not on PATH")
		}
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", args[0], msg)
	}
	return out.String(), nil
}

// hookPath returns where Git looks for the pre-commit hook, honouring
// core.hooksPath (used by husky and similar tools).
func hookPath() (string, error) {
	top, err := gitOutput("rev-parse", "--show-toplevel")
	if err != nil {
		return "", errors.New("not inside a Git repository")
	}
	top = strings.TrimSpace(top)
	if hp, err := gitOutput("config", "--get", "core.hooksPath"); err == nil && strings.TrimSpace(hp) != "" {
		dir := strings.TrimSpace(hp)
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(top, dir)
		}
		return filepath.Join(dir, "pre-commit"), nil
	}
	p, err := gitOutput("rev-parse", "--git-path", "hooks/pre-commit")
	if err != nil {
		return "", err
	}
	p = strings.TrimSpace(p)
	if !filepath.IsAbs(p) {
		p = filepath.Join(top, p)
	}
	return p, nil
}

func (c *cli) hookScript() string {
	exe, err := os.Executable()
	if err != nil {
		exe = "ven"
	}
	vaultFlag := ""
	if c.opts.vaultPath != "" {
		if abs, err := filepath.Abs(c.opts.vaultPath); err == nil {
			vaultFlag = " --vault '" + strings.ReplaceAll(filepath.ToSlash(abs), "'", `'\''`) + "'"
		}
	}
	return "#!/bin/sh\n" + hookMarker + " Remove it with `ven guard uninstall`.\n" +
		"VEN='" + strings.ReplaceAll(filepath.ToSlash(exe), "'", `'\''`) + "'\n" +
		"[ -x \"$VEN\" ] || VEN=ven\n" +
		"exec \"$VEN\"" + vaultFlag + " guard scan --staged\n"
}

func (c *cli) guardInstallCommand() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Add a pre-commit hook that runs ven guard scan --staged",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := hookPath()
			if err != nil {
				return usageErr("%v", err)
			}
			if b, err := os.ReadFile(path); err == nil && !bytes.Contains(b, []byte(hookMarker)) {
				if !force {
					return withCode(ExitConflict, fmt.Errorf("%s already exists and was not written by VEN. "+
						"Add this line to it instead:\n  ven guard scan --staged\nor pass --force to replace it (a backup is kept)", path))
				}
				if err := os.WriteFile(path+".bak", b, 0o755); err != nil {
					return err
				}
				c.infof("Saved the old hook as %s.bak", path)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(path, []byte(c.hookScript()), 0o755); err != nil {
				return err
			}
			c.successf("Installed the ven guard pre-commit hook")
			c.infof("Each commit now runs `ven guard scan --staged`.")
			if ix, err := c.loadGuard(); err == nil && ix.Len() == 0 {
				c.infof("Guard knows no secret values yet; it will learn them when you pull or import, or run ven guard index.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing pre-commit hook (keeps a .bak copy)")
	return cmd
}

func (c *cli) guardUninstallCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the ven guard pre-commit hook",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := hookPath()
			if err != nil {
				return usageErr("%v", err)
			}
			b, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) || (err == nil && !bytes.Contains(b, []byte(hookMarker))) {
				c.infof("No ven guard hook is installed here.")
				return nil
			}
			if err != nil {
				return err
			}
			if err := os.Remove(path); err != nil {
				return err
			}
			c.successf("Removed the ven guard pre-commit hook")
			return nil
		},
	}
}

func (c *cli) loadGuard() (*guard.Index, error) {
	path, err := c.guardPath()
	if err != nil {
		return nil, err
	}
	return guard.Load(path)
}

// skipDirs are never walked by folder scans.
var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv": true, "__pycache__": true}

func (c *cli) scanFolder(ix *guard.Index, root string, inRepo bool) ([]guard.Finding, error) {
	var out []guard.Finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if guard.IsEnvFile(path) {
			// Local .env files are expected; committing them is the problem.
			if inRepo {
				if _, err := gitOutput("check-ignore", "-q", path); err != nil {
					out = append(out, guard.Finding{Kind: guard.KindEnvFile, File: filepath.ToSlash(rel)})
				}
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil || bytes.IndexByte(b[:min(len(b), 8000)], 0) >= 0 {
			return nil
		}
		out = append(out, ix.ScanText(filepath.ToSlash(rel), b)...)
		return nil
	})
	return out, err
}

func (c *cli) guardScanCommand() *cobra.Command {
	var staged, history bool
	var since string
	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Look for .env files and stored secrets in files, staged changes or history",
		Long: `Look for secrets VEN knows about, and for .env files.

  ven guard scan                  the current folder (.env files only count if Git does not ignore them)
  ven guard scan src config.yml   specific folders or files
  ven guard scan --staged         what the next commit would add (used by the hook)
  ven guard scan --history        every commit in the repository
  ven guard scan --since main     commits since main

Exits with status 1 when it finds something. Findings show a masked preview,
never the secret itself.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ix, err := c.loadGuard()
			if err != nil {
				return err
			}
			var findings []guard.Finding
			switch {
			case staged || history || since != "":
				if len(args) > 0 {
					return usageErr("pass paths or --staged/--history, not both")
				}
				var diff string
				if staged {
					diff, err = gitOutput("diff", "--cached", "--no-color", "--no-ext-diff", "-U0", "-M", "--diff-filter=ACMR")
				} else {
					rng := "--all"
					if since != "" {
						rng = since + "..HEAD"
					}
					diff, err = gitOutput("log", "-p", "--no-color", "--no-ext-diff", "-U0", "-M", "--diff-filter=ACMR", "--format=%x00commit %H", rng)
				}
				if err != nil {
					return err
				}
				findings = ix.ScanDiff(diff)
			default:
				if len(args) == 0 {
					args = []string{"."}
				}
				_, repoErr := gitOutput("rev-parse", "--git-dir")
				for _, a := range args {
					info, err := os.Stat(a)
					if err != nil {
						return err
					}
					if info.IsDir() {
						f, err := c.scanFolder(ix, a, repoErr == nil)
						if err != nil {
							return err
						}
						findings = append(findings, f...)
					} else if guard.IsEnvFile(a) {
						findings = append(findings, guard.Finding{Kind: guard.KindEnvFile, File: filepath.ToSlash(a)})
					} else {
						b, err := readLimited(a, 2<<20)
						if err != nil {
							return err
						}
						findings = append(findings, ix.ScanText(filepath.ToSlash(a), b)...)
					}
				}
			}
			if ix.Len() == 0 {
				c.warnf("guard knows no secret values yet, so only .env files are checked (run ven guard index)")
			}
			if len(findings) == 0 {
				if !staged {
					c.successf("No secrets found")
				}
				return nil
			}
			c.reportFindings(findings, staged)
			return withCode(ExitError, quietError{fmt.Errorf("%d problem(s) found", len(findings))})
		},
	}
	cmd.Flags().BoolVar(&staged, "staged", false, "scan the changes staged for the next commit")
	cmd.Flags().BoolVar(&history, "history", false, "scan every commit in the repository")
	cmd.Flags().StringVar(&since, "since", "", "scan commits after this revision (e.g. main)")
	return cmd
}

func (c *cli) reportFindings(findings []guard.Finding, staged bool) {
	if staged {
		fmt.Fprintf(c.env.Err, "%s ven guard blocked this commit:\n\n", c.color(colorRed, "✗"))
	} else {
		fmt.Fprintf(c.env.Err, "%s ven guard found %d problem(s):\n\n", c.color(colorRed, "✗"), len(findings))
	}
	for _, f := range findings {
		where := f.File
		if f.Line > 0 {
			where = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		if f.Commit != "" {
			where = f.Commit + " " + where
		}
		switch f.Kind {
		case guard.KindEnvFile:
			fmt.Fprintf(c.env.Err, "  %s  %s\n", c.color(colorBold, where), c.color(colorDim, ".env file"))
		default:
			fmt.Fprintf(c.env.Err, "  %s  %s %s\n", c.color(colorBold, where), f.Name, c.color(colorDim, "("+strings.TrimPrefix(strings.TrimPrefix(f.Source, "local:"), "hosted:")+")"))
			fmt.Fprintf(c.env.Err, "      %s\n", f.Preview)
		}
	}
	fmt.Fprintln(c.env.Err)
	switch {
	case staged:
		c.infof("Unstage with `git restore --staged <file>`, add .env files to .gitignore,")
		c.infof("and read secrets from the environment instead (ven run -- <command>).")
		c.infof("If this is a false alarm: git commit --no-verify")
	case findings[0].Commit != "":
		c.infof("These secrets are in Git history. Rotate them at their source (removing the commit is not enough once pushed).")
	default:
		c.infof("Move secrets out of these files (read them from the environment with ven run), and add .env files to .gitignore.")
	}
}

func (c *cli) guardIndexCommand() *cobra.Command {
	var local, hosted bool
	cmd := &cobra.Command{
		Use:   "index",
		Short: "Refresh guard's fingerprints from your vault and shared projects",
		Long: `Decrypt your local vault and/or the shared environments you can read, and
remember fingerprints of their secret values for ven guard. Needs your
master password and/or account password. With neither flag, VEN indexes the
local vault if it exists and shared projects if you are logged in.

With --password-stdin, the master password is the first line and the
account password the next.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if !local && !hosted {
				if a, err := c.open(); err == nil {
					if st, err := a.Vault.Status(ctx); err == nil && st.Initialized {
						local = true
					}
				}
				if _, err := c.remote(); err == nil {
					hosted = true
				}
				if !local && !hosted {
					return usageErr("nothing to index: run ven init or ven login first")
				}
			}
			if local {
				a, err := c.requireInitialized(ctx)
				if err != nil {
					return err
				}
				k, err := c.unlock(ctx)
				if err != nil {
					return err
				}
				projects, err := a.Projects.List(ctx, "")
				if err != nil {
					k.Destroy()
					return err
				}
				c.guardForget("local:")
				n := 0
				for _, p := range projects {
					envs, err := storage.ListEnvironments(ctx, a.DB, p.ID)
					if err != nil {
						k.Destroy()
						return err
					}
					for _, e := range envs {
						c.rememberLocalEnv(ctx, a, k, e.ID)
						n++
					}
				}
				k.Destroy()
				c.successf("Indexed %d local environment(s)", n)
			}
			if hosted {
				cl, err := c.remote()
				if err != nil {
					return err
				}
				me, priv, err := c.unlockAccount(ctx, cl)
				if err != nil {
					return err
				}
				list, err := cl.Projects(ctx)
				if err != nil {
					return remoteErr(err)
				}
				c.guardForget("hosted:")
				n := 0
				for i := range list {
					p := &list[i]
					s := &envSession{cl: cl, project: p, priv: priv, ptype: e2e.PrincipalUser, pid: me.ID, remember: c.guardRemember}
					for _, e := range p.Environments {
						if e.Access != api.AccessActive {
							continue
						}
						o, err := s.open(ctx, e.Slug)
						if err != nil {
							c.warnf("skipped %s/%s: %v", p.Ref(), e.Slug, err)
							continue
						}
						o.wipe()
						n++
					}
				}
				c.successf("Indexed %d shared environment(s)", n)
			}
			if ix, err := c.loadGuard(); err == nil {
				c.infof("ven guard now recognises %d secret value(s).", ix.Len())
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&local, "local", false, "index the local vault")
	cmd.Flags().BoolVar(&hosted, "hosted", false, "index shared projects you can read")
	return cmd
}

func (c *cli) guardForget(prefix string) {
	path, err := c.guardPath()
	if err != nil {
		return
	}
	if ix, err := guard.Load(path); err == nil {
		ix.Forget(prefix)
		_ = ix.Save()
	}
}

func (c *cli) guardStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show what guard knows and whether this repository has the hook",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ix, err := c.loadGuard()
			if err != nil {
				return err
			}
			out := c.env.Out
			fmt.Fprintf(out, "Secret values known: %d\n", ix.Len())
			for _, s := range ix.SourceNames() {
				fmt.Fprintf(out, "  %s\n", s)
			}
			if path, err := hookPath(); err == nil {
				b, err := os.ReadFile(path)
				switch {
				case err == nil && bytes.Contains(b, []byte(hookMarker)):
					fmt.Fprintln(out, "Hook: installed in this repository")
				case err == nil:
					fmt.Fprintln(out, "Hook: another pre-commit hook is installed (add `ven guard scan --staged` to it)")
				default:
					fmt.Fprintln(out, "Hook: not installed (ven guard install)")
				}
			}
			return nil
		},
	}
}
