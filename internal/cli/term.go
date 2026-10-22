package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/term"
)

// ErrNoTerminal means input was needed but no interactive terminal exists.
var ErrNoTerminal = errors.New("input required but no interactive terminal is available")

// Terminal reads interactive input. Prompts are written to stderr, never stdout.
type Terminal interface {
	// Interactive reports whether prompts can be shown and answered.
	Interactive() bool
	// ReadPassword prompts and reads a line without echo.
	ReadPassword(prompt string) ([]byte, error)
	// ReadLine prompts and reads a visible line.
	ReadLine(prompt string) (string, error)
}

// Env holds the process streams used by commands. Tests substitute fakes.
type Env struct {
	In   io.Reader // stdin: data for --password-stdin and --value-stdin
	Out  io.Writer // stdout: command results only
	Err  io.Writer // stderr: diagnostics and prompts
	Term Terminal

	// OutIsTerminal enables trailing newlines and colors on stdout.
	OutIsTerminal bool
	// ErrIsTerminal enables colors on stderr.
	ErrIsTerminal bool

	stdinOnce sync.Once
	stdin     *bufio.Reader
}

func (e *Env) stdinReader() *bufio.Reader {
	e.stdinOnce.Do(func() { e.stdin = bufio.NewReader(e.In) })
	return e.stdin
}

// ttyTerminal reads from the controlling terminal device (/dev/tty or
// CONIN$), so prompts keep working when stdin is a pipe.
type ttyTerminal struct {
	mu     sync.Mutex
	in     *os.File
	reader *bufio.Reader
	errOut io.Writer
	ok     bool
}

var (
	activeTermMu    sync.Mutex
	activeTermFd    = -1
	activeTermState *term.State
)

// restoreTerminal undoes no-echo mode if a password prompt was interrupted.
func restoreTerminal() {
	activeTermMu.Lock()
	defer activeTermMu.Unlock()
	if activeTermState != nil {
		_ = term.Restore(activeTermFd, activeTermState)
		activeTermState = nil
	}
}

func newTTYTerminal(errOut io.Writer, stderrIsTerminal bool) *ttyTerminal {
	t := &ttyTerminal{errOut: errOut}
	if !stderrIsTerminal {
		return t
	}
	name := "/dev/tty"
	if runtime.GOOS == "windows" {
		name = "CONIN$"
	}
	f, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		return t
	}
	if !term.IsTerminal(int(f.Fd())) {
		f.Close()
		return t
	}
	t.in, t.reader, t.ok = f, bufio.NewReader(f), true
	return t
}

func (t *ttyTerminal) Interactive() bool { return t.ok }

func (t *ttyTerminal) ReadPassword(prompt string) ([]byte, error) {
	if !t.ok {
		return nil, ErrNoTerminal
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprint(t.errOut, prompt)
	fd := int(t.in.Fd())
	if st, err := term.GetState(fd); err == nil {
		activeTermMu.Lock()
		activeTermFd, activeTermState = fd, st
		activeTermMu.Unlock()
	}
	pw, err := term.ReadPassword(fd)
	activeTermMu.Lock()
	activeTermState = nil
	activeTermMu.Unlock()
	fmt.Fprintln(t.errOut)
	return pw, err
}

func (t *ttyTerminal) ReadLine(prompt string) (string, error) {
	if !t.ok {
		return "", ErrNoTerminal
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprint(t.errOut, prompt)
	line, err := t.reader.ReadString('\n')
	if err != nil && (line == "" || !errors.Is(err, io.EOF)) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// noTerminal is used with --non-interactive.
type noTerminal struct{}

func (noTerminal) Interactive() bool                   { return false }
func (noTerminal) ReadPassword(string) ([]byte, error) { return nil, ErrNoTerminal }
func (noTerminal) ReadLine(string) (string, error)     { return "", ErrNoTerminal }
