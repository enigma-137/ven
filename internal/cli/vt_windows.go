//go:build windows

package cli

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVirtualTerminal turns on ANSI escape processing for older consoles.
func enableVirtualTerminal() {
	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		h := windows.Handle(f.Fd())
		var mode uint32
		if windows.GetConsoleMode(h, &mode) == nil {
			_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
		}
	}
}
