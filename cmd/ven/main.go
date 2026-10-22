// Command ven is the VEN environment-variable vault CLI and dashboard server.
package main

import (
	"os"

	"github.com/enigma-137/ven/internal/cli"
)

func main() {
	os.Exit(cli.Main())
}
