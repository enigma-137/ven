// Package cli implements the `ven` command-line interface on top of the
// shared application services. It works without the dashboard running.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/enigma-137/ven/internal/app"
	"github.com/enigma-137/ven/internal/domain"
	"github.com/enigma-137/ven/internal/envfile"
	"github.com/enigma-137/ven/internal/storage"
	"github.com/enigma-137/ven/internal/variables"
	"github.com/enigma-137/ven/internal/vault"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Exit codes.
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitAuth        = 3 // vault not initialized, wrong password
	ExitNotFound    = 4
	ExitConflict    = 5 // already exists, destination exists, unresolved import conflicts
	ExitInputNeeded = 6 // non-interactive mode needs more flags
	ExitCancelled   = 130
)

// ErrCancelled means the user declined a confirmation.
var ErrCancelled = errors.New("cancelled")

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func withCode(code int, err error) error { return &exitError{code: code, err: err} }

func usageErr(format string, args ...any) error {
	return withCode(ExitUsage, fmt.Errorf(format, args...))
}

func needInput(format string, args ...any) error {
	return withCode(ExitInputNeeded, fmt.Errorf(format, args...))
}

func exitCode(err error) int {
	var ee *exitError
	switch {
	case err == nil:
		return ExitOK
	case errors.As(err, &ee):
		return ee.code
	case errors.Is(err, ErrCancelled):
		return ExitCancelled
	case errors.Is(err, vault.ErrNotInitialized), errors.Is(err, vault.ErrIncorrectPassword):
		return ExitAuth
	case errors.Is(err, storage.ErrNotFound):
		return ExitNotFound
	case errors.Is(err, storage.ErrConflict), errors.Is(err, envfile.ErrExists),
		errors.Is(err, variables.ErrUnresolvedConflicts), errors.Is(err, vault.ErrAlreadyInitialized):
		return ExitConflict
	case errors.Is(err, ErrNoTerminal):
		return ExitInputNeeded
	case domain.IsValidation(err):
		return ExitUsage
	}
	return ExitError
}

// options are global flags.
type options struct {
	vaultPath      string
	nonInteractive bool
	noColor        bool
	passwordStdin  bool
}

type cli struct {
	env  *Env
	opts options
	// kdf overrides Argon2id parameters (tests only).
	kdf *vault.KDFParams

	app *app.App
}

// Run executes the CLI and returns the process exit code.
func Run(ctx context.Context, args []string, env *Env) int {
	c := &cli{env: env}
	return c.run(ctx, args)
}

func (c *cli) run(ctx context.Context, args []string) int {
	root := c.rootCommand()
	root.SetArgs(args)
	root.SetIn(c.env.In)
	root.SetOut(c.env.Err) // help and usage go to stderr too, keeping stdout for data
	root.SetErr(c.env.Err)
	err := root.ExecuteContext(ctx)
	if c.app != nil {
		c.app.Close()
	}
	if err != nil {
		fmt.Fprintf(c.env.Err, "%s %s\n", c.color(colorRed, "error:"), err)
		return exitCode(err)
	}
	return ExitOK
}

// Main is the entry point used by cmd/ven.
func Main() int {
	ctx := context.Background()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	defer signal.Stop(sigs)
	go func() {
		<-sigs
		// Restore echo if a password prompt was active, then exit. Every
		// database write is transactional, so stopping here is safe.
		restoreTerminal()
		fmt.Fprintln(os.Stderr, "\ncancelled")
		os.Exit(ExitCancelled)
	}()
	enableVirtualTerminal()
	outTTY := term.IsTerminal(int(os.Stdout.Fd()))
	errTTY := term.IsTerminal(int(os.Stderr.Fd()))
	env := &Env{In: os.Stdin, Out: os.Stdout, Err: os.Stderr, OutIsTerminal: outTTY, ErrIsTerminal: errTTY}
	env.Term = newTTYTerminal(os.Stderr, errTTY)
	return Run(ctx, os.Args[1:], env)
}

func (c *cli) rootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "ven",
		Short: "VEN — a local, encrypted vault for environment variables",
		Long: `VEN stores environment variables for your projects in a local encrypted vault.

Values are encrypted with AES-256-GCM under a vault key that is wrapped by
your master password (Argon2id). There is no password recovery in V1.

Each command that reads or writes values asks for the master password;
there is no background unlock daemon. Metadata commands (listing projects,
environments and variable names) work without the password because names
are stored unencrypted.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if c.opts.nonInteractive {
				c.env.Term = noTerminal{}
			}
			return nil
		},
	}
	root.CompletionOptions.HiddenDefaultCmd = true
	pf := root.PersistentFlags()
	pf.StringVar(&c.opts.vaultPath, "vault", "", "path to the vault database (default: $VEN_VAULT or the user data directory)")
	pf.BoolVar(&c.opts.nonInteractive, "non-interactive", false, "never prompt; fail if input is required")
	pf.BoolVar(&c.opts.noColor, "no-color", false, "disable terminal colors (also honours NO_COLOR)")
	pf.BoolVar(&c.opts.passwordStdin, "password-stdin", false, "read the master password from the first line of stdin")

	root.AddCommand(
		c.initCommand(),
		c.statusCommand(),
		c.projectsCommand(),
		c.envsCommand(),
		c.importCommand(),
		c.exportCommand(),
		c.listCommand(),
		c.getCommand(),
		c.setCommand(),
		c.unsetCommand(),
		c.passwordCommand(),
		c.uiCommand(),
		c.versionCommand(),
	)
	return root
}

// open lazily opens the vault database.
func (c *cli) open() (*app.App, error) {
	if c.app != nil {
		return c.app, nil
	}
	path, err := app.ResolveVaultPath(c.opts.vaultPath)
	if err != nil {
		return nil, err
	}
	var opts []vault.Option
	if c.kdf != nil {
		opts = append(opts, vault.WithKDFParams(*c.kdf))
	}
	a, err := app.Open(path, opts...)
	if err != nil {
		return nil, err
	}
	c.app = a
	return a, nil
}

// requireInitialized fails with a helpful message for a fresh vault.
func (c *cli) requireInitialized(ctx context.Context) (*app.App, error) {
	a, err := c.open()
	if err != nil {
		return nil, err
	}
	st, err := a.Vault.Status(ctx)
	if err != nil {
		return nil, err
	}
	if !st.Initialized {
		return nil, vault.ErrNotInitialized
	}
	return a, nil
}

// readStdinLine reads one line from stdin (for --password-stdin).
func (c *cli) readStdinLine() ([]byte, error) {
	line, err := c.env.stdinReader().ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, errors.New("no master password on stdin")
	}
	return []byte(line), nil
}

// unlock obtains the vault key for this invocation.
func (c *cli) unlock(ctx context.Context) (*vault.Key, error) {
	a, err := c.requireInitialized(ctx)
	if err != nil {
		return nil, err
	}
	if c.opts.passwordStdin {
		pw, err := c.readStdinLine()
		if err != nil {
			return nil, err
		}
		defer vault.Wipe(pw)
		return a.Vault.Unlock(ctx, pw)
	}
	if !c.env.Term.Interactive() {
		return nil, needInput("the master password is required: run in a terminal or pass --password-stdin")
	}
	for attempt := 1; ; attempt++ {
		pw, err := c.env.Term.ReadPassword("Master password: ")
		if err != nil {
			return nil, err
		}
		k, err := a.Vault.Unlock(ctx, pw)
		vault.Wipe(pw)
		if errors.Is(err, vault.ErrIncorrectPassword) && attempt < 3 {
			c.warnf("Incorrect master password, try again.")
			continue
		}
		return k, err
	}
}

// confirm asks a yes/no question. defaultYes controls the empty answer.
func (c *cli) confirm(question string, defaultYes bool) (bool, error) {
	hint := "[y/N]"
	if defaultYes {
		hint = "[Y/n]"
	}
	ans, err := c.env.Term.ReadLine(question + " " + hint + " ")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(ans)) {
	case "":
		return defaultYes, nil
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// choose prints numbered options and returns the selected index.
func (c *cli) choose(title string, items []string) (int, error) {
	if len(items) == 0 {
		return -1, errors.New("nothing to choose from")
	}
	fmt.Fprintln(c.env.Err, title)
	for i, it := range items {
		fmt.Fprintf(c.env.Err, "  %d) %s\n", i+1, it)
	}
	for {
		ans, err := c.env.Term.ReadLine(fmt.Sprintf("Select 1-%d: ", len(items)))
		if err != nil {
			return -1, err
		}
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(ans), "%d", &n); err == nil && n >= 1 && n <= len(items) {
			return n - 1, nil
		}
		if strings.TrimSpace(ans) == "" {
			return -1, ErrCancelled
		}
		c.warnf("Please enter a number between 1 and %d.", len(items))
	}
}

func (c *cli) infof(format string, args ...any) {
	fmt.Fprintf(c.env.Err, format+"\n", args...)
}

func (c *cli) warnf(format string, args ...any) {
	fmt.Fprintf(c.env.Err, "%s %s\n", c.color(colorYellow, "warning:"), fmt.Sprintf(format, args...))
}

func (c *cli) successf(format string, args ...any) {
	fmt.Fprintf(c.env.Err, "%s %s\n", c.color(colorGreen, "✓"), fmt.Sprintf(format, args...))
}

const (
	colorRed    = "31"
	colorGreen  = "32"
	colorYellow = "33"
	colorDim    = "2"
	colorBold   = "1"
)

func (c *cli) colorsEnabled() bool {
	return c.env.ErrIsTerminal && !c.opts.noColor && os.Getenv("NO_COLOR") == ""
}

// color wraps s for stderr output.
func (c *cli) color(code, s string) string {
	if !c.colorsEnabled() {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// table writes aligned columns to w.
func table(w io.Writer, header []string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	tw.Flush()
}

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
	return t.Local().Format("2006-01-02")
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
