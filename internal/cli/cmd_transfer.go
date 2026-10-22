package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/enigma-137/ven/internal/envfile"
	"github.com/enigma-137/ven/internal/variables"
	"github.com/spf13/cobra"
)

func (c *cli) importCommand() *cobra.Command {
	var tf targetFlags
	var replace, yes, create, dryRun bool
	var onConflict string
	var types []string
	cmd := &cobra.Command{
		Use:   "import <file> --project <project> --env <environment>",
		Short: "Import a dotenv file (preview first, commit in one transaction)",
		Long: `Import variables from a dotenv file.

VEN parses the file (see docs/dotenv.md for the grammar), reports malformed
lines by line number without printing values, and shows a preview of new,
changed and unchanged keys before writing anything. The accepted import is
committed in a single transaction: a cancelled or failed import leaves the
environment untouched. Nothing in the file is executed or expanded.

Modes:
  merge (default)  add new keys and update changed ones; other keys stay
  --replace        make the environment match the file, removing keys that
                   are not in it (requires confirmation or --yes)

Conflicts (keys whose stored value differs) are resolved interactively, or
with --on-conflict overwrite|keep. Non-interactive imports with conflicts
fail unless --on-conflict is given.`,
		Example: `  ven import .env --project api --env development
  ven import .env.production -p api -e production --replace
  ven import .env -p api -e staging --on-conflict keep --non-interactive
  ven import .env -p new-app -e development --create --type PUBLIC_URL=text`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			var resolution variables.Resolution
			switch onConflict {
			case "", "ask":
			case "overwrite":
				resolution = variables.Overwrite
			case "keep":
				resolution = variables.Keep
			default:
				return usageErr("--on-conflict must be overwrite, keep or ask")
			}
			typeOverrides := map[string]string{}
			for _, t := range types {
				k, v, ok := strings.Cut(t, "=")
				if !ok || !variables.ValidType(v) {
					return usageErr("--type must look like KEY=secret or KEY=text")
				}
				typeOverrides[k] = v
			}
			mode := variables.ModeMerge
			if replace {
				mode = variables.ModeReplace
			}

			// 1. Read and parse before touching the vault.
			src, err := readLimited(args[0], envfile.MaxFileSize)
			if err != nil {
				return err
			}
			parsed := envfile.Parse(src)
			clear(src)
			for _, is := range parsed.Issues {
				if is.Severity == envfile.SeverityError {
					fmt.Fprintf(c.env.Err, "  %s line %d: %s\n", c.color(colorRed, "error"), is.Line, is.Message)
				} else {
					fmt.Fprintf(c.env.Err, "  %s line %d: %s\n", c.color(colorYellow, "warning"), is.Line, is.Message)
				}
			}
			if parsed.HasErrors() {
				return fmt.Errorf("%s has %d error(s); nothing was imported", args[0], len(parsed.Errors()))
			}
			if len(parsed.Entries) == 0 && mode == variables.ModeMerge {
				c.infof("%s contains no variables; nothing to import.", args[0])
				return nil
			}

			// 2. Resolve the target; creation is deferred until confirmation.
			a, err := c.requireInitialized(ctx)
			if err != nil {
				return err
			}
			t, err := c.resolveTarget(ctx, a, tf.project, tf.env, true, create)
			if err != nil {
				return err
			}

			// 3. Unlock and plan.
			k, err := c.unlock(ctx)
			if err != nil {
				return err
			}
			defer k.Destroy()
			plan, err := a.Variables.PlanImport(ctx, k, t.env.ID, parsed.Entries, mode)
			if err != nil {
				return err
			}
			for key, typ := range typeOverrides {
				for i := range plan.Items {
					if plan.Items[i].Key == key {
						plan.Items[i].Type = typ
					}
				}
			}
			c.printPlan(t, plan)
			if dryRun {
				c.infof("Dry run: nothing was written.")
				return nil
			}

			// 4. Conflicts.
			opts := variables.ImportOptions{Mode: mode, OnConflict: resolution, Types: typeOverrides, Resolutions: map[string]variables.Resolution{}}
			if conflicts := plan.Conflicts(); len(conflicts) > 0 && resolution == "" {
				if !c.env.Term.Interactive() {
					return withCode(ExitConflict, fmt.Errorf("%d key(s) have different stored values; pass --on-conflict overwrite or keep", len(conflicts)))
				}
				if err := c.resolveConflicts(conflicts, &opts); err != nil {
					return err
				}
			}

			// 5. Replace confirmation.
			if mode == variables.ModeReplace {
				if plan.Counts.Removed > 0 && !yes {
					if !c.env.Term.Interactive() {
						return needInput("replace mode would remove %d variable(s); pass --yes to confirm", plan.Counts.Removed)
					}
					c.warnf("Replace mode will permanently remove %d variable(s) that are not in the file.", plan.Counts.Removed)
					ans, err := c.env.Term.ReadLine("Type 'replace' to confirm: ")
					if err != nil {
						return err
					}
					if strings.TrimSpace(ans) != "replace" {
						return ErrCancelled
					}
				}
				opts.ConfirmReplace = true
			}

			// 6. Final confirmation.
			if !yes && c.env.Term.Interactive() {
				ok, err := c.confirm(fmt.Sprintf("Import into %s?", t.label()), true)
				if err != nil {
					return err
				}
				if !ok {
					return ErrCancelled
				}
			}

			// 7. Create missing project/environment, then commit atomically.
			cleanup, err := c.materialize(ctx, a, &t)
			if err != nil {
				return err
			}
			res, err := a.Variables.ApplyImport(ctx, k, t.env.ID, parsed.Entries, opts)
			if err != nil {
				cleanup()
				return fmt.Errorf("import failed; nothing was changed: %w", err)
			}
			c.successf("Imported into %s: %d created, %d updated, %d kept, %d unchanged, %d removed",
				t.label(), res.Created, res.Updated, res.Kept, res.Unchanged, res.Removed)
			return nil
		},
	}
	tf.register(cmd)
	cmd.Flags().BoolVar(&replace, "replace", false, "remove existing variables that are not in the file")
	cmd.Flags().StringVar(&onConflict, "on-conflict", "", "resolve changed keys: overwrite, keep or ask (default ask)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip confirmation prompts (including replace removals)")
	cmd.Flags().BoolVar(&create, "create", false, "create the project or environment if it does not exist")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the preview without importing")
	cmd.Flags().StringArrayVar(&types, "type", nil, "override the display type of a key: KEY=secret or KEY=text (repeatable)")
	return cmd
}

func (c *cli) printPlan(t target, plan *variables.ImportPlan) {
	c.infof("Import preview for %s (%s mode):", t.label(), plan.Mode)
	var rows [][]string
	for _, it := range plan.Items {
		status := string(it.Status)
		switch it.Status {
		case variables.StatusNew:
			status = c.color(colorGreen, status)
		case variables.StatusChanged:
			status = c.color(colorYellow, status)
		case variables.StatusRemoved:
			status = c.color(colorRed, status)
		case variables.StatusUnchanged:
			status = c.color(colorDim, status)
		}
		line := ""
		if it.Line > 0 {
			line = fmt.Sprint(it.Line)
		}
		rows = append(rows, []string{it.Key, status, it.Type, line})
	}
	table(c.env.Err, []string{"KEY", "STATUS", "TYPE", "LINE"}, rows)
	n := plan.Counts
	c.infof("%d new, %d changed, %d unchanged, %d to remove", n.New, n.Changed, n.Unchanged, n.Removed)
}

func (c *cli) resolveConflicts(conflicts []string, opts *variables.ImportOptions) error {
	c.warnf("%d key(s) already exist with different values: %s", len(conflicts), strings.Join(conflicts, ", "))
	for {
		ans, err := c.env.Term.ReadLine("[o]verwrite all, [k]eep all existing, [c]hoose per key, [a]bort: ")
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(ans)) {
		case "o", "overwrite":
			opts.OnConflict = variables.Overwrite
			return nil
		case "k", "keep":
			opts.OnConflict = variables.Keep
			return nil
		case "c", "choose":
			for _, key := range conflicts {
				ok, err := c.confirm(fmt.Sprintf("  Overwrite %s with the value from the file?", key), false)
				if err != nil {
					return err
				}
				if ok {
					opts.Resolutions[key] = variables.Overwrite
				} else {
					opts.Resolutions[key] = variables.Keep
				}
			}
			return nil
		case "a", "abort", "":
			return ErrCancelled
		}
	}
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than the %d byte import limit", path, limit)
	}
	return b, nil
}

func (c *cli) exportCommand() *cobra.Command {
	var tf targetFlags
	var out string
	var force, stdout, yes bool
	cmd := &cobra.Command{
		Use:   "export [--project <project> --env <environment>] [--out .env | --stdout]",
		Short: "Export an environment as a plaintext dotenv file",
		Long: `Export an environment as a dotenv file.

WARNING: exported dotenv files contain plaintext credentials. Keep them out
of version control and delete them when no longer needed.

Without --project/--env, VEN asks interactively. The default destination is
.env in the current directory. Existing files are never overwritten silently:
VEN asks in interactive mode and fails otherwise unless --force is given.
Files are written atomically with 0600 permissions where the OS supports it.

With --stdout the dotenv content goes to stdout for piping; all prompts and
diagnostics go to stderr.`,
		Example: `  ven export
  ven export --project api --env development --out .env
  ven export -p api -e production --out .env.production --force
  ven export -p api -e staging --stdout > staging.env`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if stdout && cmd.Flags().Changed("out") {
				return usageErr("--stdout and --out cannot be combined")
			}
			a, err := c.requireInitialized(ctx)
			if err != nil {
				return err
			}
			t, err := c.resolveTarget(ctx, a, tf.project, tf.env, false, false)
			if err != nil {
				return err
			}

			var dest string
			exists := false
			if !stdout {
				dest, err = filepath.Abs(out)
				if err != nil {
					return err
				}
				if info, err := os.Stat(dest); err == nil {
					if info.IsDir() {
						return fmt.Errorf("%s is a directory", dest)
					}
					exists = true
				}
			}

			// Preview without values.
			c.infof("Project:      %s (%s)", t.project.Name, t.project.Slug)
			c.infof("Environment:  %s (%s)", t.env.Name, t.env.Slug)
			c.infof("Variables:    %d", t.env.VariableCount)
			if stdout {
				c.infof("Destination:  stdout")
			} else {
				note := ""
				if exists {
					note = c.color(colorYellow, " (exists)")
				}
				c.infof("Destination:  %s%s", dest, note)
				c.warnf("dotenv exports contain plaintext values.")
			}

			if exists && !force {
				if !c.env.Term.Interactive() {
					return withCode(ExitConflict, fmt.Errorf("%w: %s (use --force to overwrite)", envfile.ErrExists, dest))
				}
				ok, err := c.confirm("Overwrite the existing file?", false)
				if err != nil {
					return err
				}
				if !ok {
					return ErrCancelled
				}
				force = true
			} else if !stdout && !yes && c.env.Term.Interactive() {
				ok, err := c.confirm("Write the file?", true)
				if err != nil {
					return err
				}
				if !ok {
					return ErrCancelled
				}
			}

			k, err := c.unlock(ctx)
			if err != nil {
				return err
			}
			defer k.Destroy()
			data, n, err := a.Variables.Export(ctx, k, t.env.ID)
			if err != nil {
				return err
			}
			defer clear(data)
			if stdout {
				_, err := c.env.Out.Write(data)
				return err
			}
			if err := envfile.WriteFile(dest, data, force); err != nil {
				if errors.Is(err, envfile.ErrExists) {
					return withCode(ExitConflict, err)
				}
				return err
			}
			c.successf("Wrote %d variable(s) to %s", n, dest)
			return nil
		},
	}
	tf.register(cmd)
	cmd.Flags().StringVarP(&out, "out", "o", ".env", "destination file")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite the destination if it exists")
	cmd.Flags().BoolVar(&stdout, "stdout", false, "write dotenv content to stdout instead of a file")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the write confirmation prompt")
	return cmd
}
