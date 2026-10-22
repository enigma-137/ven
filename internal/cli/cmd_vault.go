package cli

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/enigma-137/ven/internal/app"
	"github.com/enigma-137/ven/internal/storage"
	"github.com/enigma-137/ven/internal/vault"
	"github.com/spf13/cobra"
)

const noRecoveryNotice = `Nobody can reset the master password for you. VEN gives you a one-time
recovery key instead: keep it somewhere safe (a password manager or on paper).
Without the password and the recovery key, nobody can decrypt this vault.`

// printRecoveryKey shows a recovery key once: the key on stdout (so scripts
// can capture it), the explanation on stderr.
func (c *cli) printRecoveryKey(key, resetCmd string) {
	c.infof("")
	c.infof("%s", c.color(colorBold, "Your recovery key (shown once):"))
	c.infof("")
	fmt.Fprintln(c.env.Out, key)
	c.infof("")
	c.infof("Save it in a password manager or write it down, away from this computer.")
	c.infof("If you forget your password: %s", resetCmd)
	c.infof("Anyone with this key can set a new password, so keep it private.")
}

// readNewPassword asks for a new master password twice.
func (c *cli) readNewPassword(label string) ([]byte, error) {
	if c.opts.passwordStdin {
		pw, err := c.readStdinLine()
		if err != nil {
			return nil, err
		}
		return pw, vault.ValidatePassword(pw)
	}
	if !c.env.Term.Interactive() {
		return nil, needInput("a new master password is required: run in a terminal or pass --password-stdin")
	}
	for {
		pw, err := c.env.Term.ReadPassword(label + ": ")
		if err != nil {
			return nil, err
		}
		if err := vault.ValidatePassword(pw); err != nil {
			vault.Wipe(pw)
			c.warnf("%s", err)
			continue
		}
		again, err := c.env.Term.ReadPassword("Confirm " + strings.ToLower(label) + ": ")
		if err != nil {
			vault.Wipe(pw)
			return nil, err
		}
		match := string(again) == string(pw)
		vault.Wipe(again)
		if !match {
			vault.Wipe(pw)
			c.warnf("Passwords do not match, try again.")
			continue
		}
		return pw, nil
	}
}

func (c *cli) initCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create a new vault protected by a master password",
		Long: "Create a new vault protected by a master password.\n\n" + noRecoveryNotice + "\n\n" +
			fmt.Sprintf("The master password must be at least %d characters.", vault.MinPasswordLength),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := c.open()
			if err != nil {
				return err
			}
			st, err := a.Vault.Status(ctx)
			if err != nil {
				return err
			}
			if st.Initialized {
				return fmt.Errorf("%w at %s", vault.ErrAlreadyInitialized, a.DB.Path)
			}
			c.infof("Creating a vault at %s\n", a.DB.Path)
			c.infof("%s\n", noRecoveryNotice)
			pw, err := c.readNewPassword("Master password")
			if err != nil {
				return err
			}
			defer vault.Wipe(pw)
			k, err := a.Vault.Init(ctx, pw)
			if err != nil {
				return err
			}
			defer k.Destroy()
			c.successf("Vault created.")
			rk, err := a.Vault.CreateRecoveryKey(ctx, k)
			if err != nil {
				return fmt.Errorf("vault created, but the recovery key failed (run ven password recovery-key): %w", err)
			}
			c.printRecoveryKey(rk, "ven password reset")
			c.infof("")
			c.infof("Next: ven projects create <name>")
			return nil
		},
	}
}

func (c *cli) statusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show vault location and state (does not need the password)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := c.open()
			if err != nil {
				return err
			}
			st, err := a.Vault.Status(ctx)
			if err != nil {
				return err
			}
			schema, _ := a.DB.SchemaVersion(ctx)
			out := c.env.Out
			fmt.Fprintf(out, "Vault:        %s\n", a.DB.Path)
			if !st.Initialized {
				fmt.Fprintln(out, "State:        not initialized (run `ven init`)")
				return nil
			}
			n, err := storage.CountProjects(ctx, a.DB)
			if err != nil {
				return err
			}
			fmt.Fprintln(out, "State:        initialized, locked (each command unlocks on demand)")
			fmt.Fprintf(out, "Projects:     %d\n", n)
			fmt.Fprintf(out, "Created:      %s\n", storage.ParseTime(st.CreatedAt).Local().Format("2006-01-02 15:04"))
			fmt.Fprintf(out, "Key wrapping: argon2id (m=%d MiB, t=%d, p=%d) + AES-256-GCM\n", st.KDF.Memory/1024, st.KDF.Iterations, st.KDF.Parallelism)
			if has, err := a.Vault.HasRecoveryKey(ctx); err == nil {
				if has {
					fmt.Fprintln(out, "Recovery key: set")
				} else {
					fmt.Fprintln(out, "Recovery key: not set (create one with `ven password recovery-key`)")
				}
			}
			fmt.Fprintf(out, "Schema:       v%d\n", schema)
			fmt.Fprintf(out, "Version:      %s\n", app.Version)
			return nil
		},
	}
}

func (c *cli) passwordCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "password",
		Short: "Change, reset or recover the master password",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "change",
		Short: "Change the master password",
		Long: "Change the master password. The vault key is re-wrapped with a key derived from the new\n" +
			"password; stored values are not re-encrypted and remain intact.\n\n" + noRecoveryNotice,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := c.requireInitialized(ctx)
			if err != nil {
				return err
			}
			if c.opts.passwordStdin {
				return usageErr("password change is interactive only")
			}
			if !c.env.Term.Interactive() {
				return needInput("password change requires an interactive terminal")
			}
			cur, err := c.env.Term.ReadPassword("Current master password: ")
			if err != nil {
				return err
			}
			defer vault.Wipe(cur)
			// Verify first so a typo is reported before asking for the new one.
			k, err := a.Vault.Unlock(ctx, cur)
			if err != nil {
				return err
			}
			k.Destroy()
			next, err := c.readNewPassword("New master password")
			if err != nil {
				return err
			}
			defer vault.Wipe(next)
			if err := a.Vault.ChangePassword(ctx, cur, next); err != nil {
				if errors.Is(err, vault.ErrIncorrectPassword) {
					return err
				}
				return fmt.Errorf("change password: %w", err)
			}
			c.successf("Master password changed.")
			return nil
		},
	})
	var yes bool
	recoveryKey := &cobra.Command{
		Use:   "recovery-key",
		Short: "Create a new recovery key (replaces the old one)",
		Long: `Create a recovery key for this vault, or replace the existing one. The old
recovery key stops working. Needs the master password.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := c.requireInitialized(ctx)
			if err != nil {
				return err
			}
			has, err := a.Vault.HasRecoveryKey(ctx)
			if err != nil {
				return err
			}
			if has && !yes {
				if !c.env.Term.Interactive() {
					return needInput("this replaces your current recovery key; pass --yes to confirm")
				}
				ok, err := c.confirm("Replace your current recovery key? The old one will stop working.", false)
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
			rk, err := a.Vault.CreateRecoveryKey(ctx, k)
			if err != nil {
				return err
			}
			c.successf("Recovery key created.")
			c.printRecoveryKey(rk, "ven password reset")
			return nil
		},
	}
	recoveryKey.Flags().BoolVarP(&yes, "yes", "y", false, "replace an existing recovery key without asking")
	cmd.AddCommand(recoveryKey)
	cmd.AddCommand(&cobra.Command{
		Use:   "reset",
		Short: "Set a new master password using your recovery key",
		Long: `Forgot the master password? Enter your recovery key and choose a new password.
Your values are untouched and the recovery key keeps working.

With --password-stdin, the first line of stdin is the recovery key and the
second line the new password.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := c.requireInitialized(ctx)
			if err != nil {
				return err
			}
			var rk []byte
			if c.opts.passwordStdin {
				if rk, err = c.readStdinLine(); err != nil {
					return err
				}
			} else {
				if !c.env.Term.Interactive() {
					return needInput("the recovery key is required: run in a terminal or pass --password-stdin")
				}
				if rk, err = c.env.Term.ReadPassword("Recovery key: "); err != nil {
					return err
				}
			}
			defer vault.Wipe(rk)
			if _, err := vault.ParseRecoveryKey(vault.VaultRecoveryPrefix, string(rk)); err != nil {
				return usageErr("%v", err)
			}
			next, err := c.readNewPassword("New master password")
			if err != nil {
				return err
			}
			defer vault.Wipe(next)
			if err := a.Vault.ResetPassword(ctx, string(rk), next); err != nil {
				return err
			}
			c.successf("Master password reset. Your values are untouched.")
			return nil
		},
	})
	return cmd
}

func (c *cli) versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the VEN version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(c.env.Out, "ven %s (%s/%s, %s)\n", app.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
			return nil
		},
	}
}
