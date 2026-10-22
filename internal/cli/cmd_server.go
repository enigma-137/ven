package cli

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/enigma-137/ven/internal/remote/server"
	"github.com/spf13/cobra"
)

func (c *cli) serverCommand() *cobra.Command {
	var listen, dbPath, githubClientID string
	var trustProxy, quiet bool
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the hosted VEN server (accounts, teams, sharing)",
		Long: `Run the hosted VEN API that ven login, pull, push, share and join talk to.

The server stores only ciphertext, memberships and an audit log in SQLite.
It never sees plaintext values, private keys or invite/token secrets.

Run it on loopback behind a TLS-terminating reverse proxy (Caddy, nginx).
Configuration can come from flags or environment variables:

  VEN_SERVER_LISTEN      address to listen on      (default 127.0.0.1:4100)
  VEN_SERVER_DB          SQLite database path      (required)
  VEN_GITHUB_CLIENT_ID   GitHub OAuth app client ID, with device flow enabled (required)
  VEN_TRUST_PROXY        "1" to read client IPs from X-Forwarded-For sent by a loopback proxy`,
		Example: `  ven server --db /home/traceiq/ven/data/server.db --github-client-id Iv1.abc123 --trust-proxy`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if listen == "" {
				listen = envOr("VEN_SERVER_LISTEN", "127.0.0.1:4100")
			}
			if dbPath == "" {
				dbPath = os.Getenv("VEN_SERVER_DB")
			}
			if githubClientID == "" {
				githubClientID = os.Getenv("VEN_GITHUB_CLIENT_ID")
			}
			if !cmd.Flags().Changed("trust-proxy") {
				trustProxy = os.Getenv("VEN_TRUST_PROXY") == "1"
			}
			if dbPath == "" {
				return usageErr("--db (or VEN_SERVER_DB) is required")
			}
			if githubClientID == "" {
				return usageErr("--github-client-id (or VEN_GITHUB_CLIENT_ID) is required")
			}
			cfg := server.Config{DBPath: dbPath, GitHubClientID: githubClientID, TrustProxy: trustProxy}
			if !quiet {
				cfg.Logger = log.New(c.env.Err, "", log.LstdFlags)
			}
			srv, err := server.New(cfg)
			if err != nil {
				return err
			}
			defer srv.Close()
			ln, err := net.Listen("tcp", listen)
			if err != nil {
				return err
			}
			if host, _, _ := net.SplitHostPort(listen); host != "127.0.0.1" && host != "localhost" && host != "::1" {
				c.warnf("listening on %s: the server speaks plain HTTP and should sit behind a TLS proxy on loopback", listen)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			fmt.Fprintf(c.env.Err, "VEN server listening on http://%s (database %s)\n", ln.Addr(), dbPath)
			return srv.Serve(ctx, ln)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "address to listen on (default 127.0.0.1:4100)")
	cmd.Flags().StringVar(&dbPath, "db", "", "SQLite database path")
	cmd.Flags().StringVar(&githubClientID, "github-client-id", "", "GitHub OAuth app client ID (device flow enabled)")
	cmd.Flags().BoolVar(&trustProxy, "trust-proxy", false, "trust X-Forwarded-For from a loopback reverse proxy")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "do not log requests")
	return cmd
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
