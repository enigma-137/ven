package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/enigma-137/ven/internal/envfile"
	"github.com/enigma-137/ven/internal/storage"
	"github.com/enigma-137/ven/internal/variables"
	"github.com/enigma-137/ven/internal/vault"
	"github.com/spf13/cobra"
)

const masked = "••••••••"

type targetFlags struct {
	project string
	env     string
}

func (f *targetFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.project, "project", "p", "", "project slug or name")
	cmd.Flags().StringVarP(&f.env, "env", "e", "", "environment slug or name")
}

func (c *cli) listCommand() *cobra.Command {
	var tf targetFlags
	var search string
	cmd := &cobra.Command{
		Use:   "list --project <project> --env <environment>",
		Short: "List variable keys and metadata (values masked; no password needed)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := c.requireInitialized(ctx)
			if err != nil {
				return err
			}
			t, err := c.resolveTarget(ctx, a, tf.project, tf.env, false, false)
			if err != nil {
				return err
			}
			list, err := a.Variables.List(ctx, t.env.ID, search)
			if err != nil {
				return err
			}
			if len(list) == 0 {
				if search != "" {
					c.infof("No variables in %s match %q.", t.label(), search)
				} else {
					c.infof("%s has no variables. Add one with `ven set <KEY>` or `ven import <file>`.", t.label())
				}
				return nil
			}
			var rows [][]string
			for _, v := range list {
				rows = append(rows, []string{v.Key, masked, v.Type, ago(v.UpdatedAt), truncate(v.Description, 40)})
			}
			table(c.env.Out, []string{"KEY", "VALUE", "TYPE", "UPDATED", "DESCRIPTION"}, rows)
			return nil
		},
	}
	tf.register(cmd)
	cmd.Flags().StringVarP(&search, "search", "s", "", "filter by key or description")
	return cmd
}

func (c *cli) getCommand() *cobra.Command {
	var tf targetFlags
	cmd := &cobra.Command{
		Use:   "get <KEY> --project <project> --env <environment>",
		Short: "Print one decrypted value to stdout",
		Long: "Print one decrypted value to stdout. The value is printed in plaintext;\n" +
			"a trailing newline is added only when stdout is a terminal.",
		Example: `  ven get DATABASE_URL -p api -e production
  export TOKEN="$(ven get API_TOKEN -p api -e development)"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := c.requireInitialized(ctx)
			if err != nil {
				return err
			}
			t, err := c.resolveTarget(ctx, a, tf.project, tf.env, false, false)
			if err != nil {
				return err
			}
			// Report a missing key before asking for the password.
			if _, err := storage.GetVariableByKey(ctx, a.DB, t.env.ID, args[0]); err != nil {
				return fmt.Errorf("variable %s in %s: %w", args[0], t.label(), err)
			}
			k, err := c.unlock(ctx)
			if err != nil {
				return err
			}
			defer k.Destroy()
			_, value, err := a.Variables.Get(ctx, k, t.env.ID, args[0])
			if err != nil {
				return err
			}
			io.WriteString(c.env.Out, value)
			if c.env.OutIsTerminal {
				fmt.Fprintln(c.env.Out)
			}
			return nil
		},
	}
	tf.register(cmd)
	return cmd
}

func (c *cli) setCommand() *cobra.Command {
	var tf targetFlags
	var typ, desc string
	var valueStdin bool
	cmd := &cobra.Command{
		Use:   "set <KEY> --project <project> --env <environment>",
		Short: "Create or update a variable (value read with hidden input)",
		Long: "Create or update a variable. The value is read with hidden input, or from stdin\n" +
			"with --value-stdin (one trailing newline is removed). Combined with --password-stdin,\n" +
			"the first stdin line is the master password and the rest is the value.\n\n" +
			"Values are never accepted as command-line arguments, which would leak into shell\n" +
			"history and process lists.\n\n" +
			"New keys are classified as secret or text from their name; override with --type.",
		Example: `  ven set STRIPE_SECRET_KEY -p billing -e production
  printf '%s' "$VALUE" | ven set API_TOKEN -p api -e dev --value-stdin
  ven set LOG_LEVEL -p api -e dev --type text --description "zap log level"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			key := args[0]
			if err := variables.ValidateKey(key); err != nil {
				return err
			}
			if typ != "" && !variables.ValidType(typ) {
				return usageErr("--type must be secret or text")
			}
			a, err := c.requireInitialized(ctx)
			if err != nil {
				return err
			}
			t, err := c.resolveTarget(ctx, a, tf.project, tf.env, false, false)
			if err != nil {
				return err
			}

			// With --password-stdin the first stdin line is the password and,
			// with --value-stdin, the rest is the value.
			var k *vault.Key
			if c.opts.passwordStdin {
				if k, err = c.unlock(ctx); err != nil {
					return err
				}
				defer k.Destroy()
			}
			var value string
			if valueStdin {
				b, err := io.ReadAll(io.LimitReader(c.env.stdinReader(), envfile.MaxValueSize+2))
				if err != nil {
					return err
				}
				value = strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
			} else {
				if !c.env.Term.Interactive() {
					return needInput("a value is required: run in a terminal or pass --value-stdin")
				}
				b, err := c.env.Term.ReadPassword(fmt.Sprintf("Value for %s (hidden): ", key))
				if err != nil {
					return err
				}
				value = string(b)
				clear(b)
			}
			if err := variables.ValidateValue(value); err != nil {
				return err
			}

			if k == nil {
				if k, err = c.unlock(ctx); err != nil {
					return err
				}
				defer k.Destroy()
			}
			in := variables.SetInput{Key: key, Value: value, Type: typ}
			if cmd.Flags().Changed("description") {
				in.Description = &desc
			}
			v, created, err := a.Variables.Set(ctx, k, t.env.ID, in)
			if err != nil {
				return err
			}
			verb := "Updated"
			if created {
				verb = "Created"
			}
			c.successf("%s %s in %s (%s)", verb, v.Key, t.label(), v.Type)
			return nil
		},
	}
	tf.register(cmd)
	cmd.Flags().StringVar(&typ, "type", "", "display type: secret or text (default: keep existing or classify)")
	cmd.Flags().StringVar(&desc, "description", "", "optional description")
	cmd.Flags().BoolVar(&valueStdin, "value-stdin", false, "read the value from stdin instead of prompting")
	return cmd
}

func (c *cli) unsetCommand() *cobra.Command {
	var tf targetFlags
	cmd := &cobra.Command{
		Use:     "unset <KEY> --project <project> --env <environment>",
		Aliases: []string{"rm"},
		Short:   "Delete a variable",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := c.requireInitialized(ctx)
			if err != nil {
				return err
			}
			t, err := c.resolveTarget(ctx, a, tf.project, tf.env, false, false)
			if err != nil {
				return err
			}
			v, err := a.Variables.Delete(ctx, t.env.ID, args[0])
			if err != nil {
				return err
			}
			c.successf("Removed %s from %s", v.Key, t.label())
			return nil
		},
	}
	tf.register(cmd)
	return cmd
}
