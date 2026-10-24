package cli

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strconv"

	"github.com/enigma-137/ven/internal/server"
	"github.com/enigma-137/ven/web"
	"github.com/spf13/cobra"
)

// DefaultUIPort is tried first by `ven ui`.
const DefaultUIPort = 7420

func (c *cli) uiCommand() *cobra.Command {
	var port int
	var noBrowser, verbose bool
	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Start the local dashboard on 127.0.0.1",
		Long: `Start the dashboard on a loopback address (127.0.0.1 only) and open it in
your browser. The printed link contains a one-time launch token in the URL
fragment; only a browser holding it can start a dashboard session.

The dashboard asks for the master password, auto-locks after inactivity
(configurable in Settings) and locks when this command stops. Press Ctrl+C
to stop the server.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := c.open()
			if err != nil {
				return err
			}
			ln, err := listenLoopback(port, cmd.Flags().Changed("port"))
			if err != nil {
				return err
			}
			logger := log.New(discardWriter{}, "", 0)
			if verbose {
				logger = log.New(c.env.Err, "ven ui: ", log.LstdFlags)
			}
			static := web.Dist()
			if static == nil {
				c.warnf("this binary was built without the dashboard frontend; run `make build` to embed it")
			}
			token := server.NewLaunchToken()
			srv := server.New(server.Config{App: a, LaunchToken: token, Static: static, Logger: logger})
			url := fmt.Sprintf("http://%s/#launch=%s", ln.Addr().String(), token)

			c.infof("VEN dashboard listening on http://%s (loopback only)", ln.Addr().String())
			c.infof("Open this link to start a session (keep it private):\n\n  %s\n", url)
			c.infof("Press Ctrl+C to stop. The vault locks when the server stops.")
			if !noBrowser {
				if err := openBrowser(url); err != nil {
					c.warnf("could not open a browser automatically; open the link above")
				}
			}
			return srv.Serve(cmd.Context(), ln)
		},
	}
	cmd.Flags().IntVar(&port, "port", DefaultUIPort, "port on 127.0.0.1 (0 picks a free port)")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "do not open a browser")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "log requests (method, path, status) to stderr")
	return cmd
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// listenLoopback binds 127.0.0.1:port. If the default port is busy and no
// port was requested explicitly, it falls back to a free port.
func listenLoopback(port int, explicit bool) (net.Listener, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err == nil || explicit {
		return ln, err
	}
	return net.Listen("tcp", "127.0.0.1:0")
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		// WSL usually has no xdg-open; wslview and explorer.exe open the
		// Windows browser.
		for _, name := range []string{"xdg-open", "wslview", "explorer.exe"} {
			if _, err := exec.LookPath(name); err == nil {
				cmd = exec.Command(name, url)
				break
			}
		}
		if cmd == nil {
			return errors.New("no browser opener found")
		}
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}
