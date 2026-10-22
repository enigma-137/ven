package envfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrExists is returned when the destination exists and overwrite was not requested.
var ErrExists = errors.New("destination file already exists")

// Header is written at the top of every export.
const Header = "# Exported by VEN. This file contains plaintext values; keep it out of version control.\n"

// Serialize renders entries in VEN's canonical dotenv form. Every value
// parses back to exactly the same string with Parse.
func Serialize(entries []Entry) []byte {
	var b strings.Builder
	b.WriteString(Header)
	for _, e := range entries {
		b.WriteString(e.Key)
		b.WriteByte('=')
		b.WriteString(QuoteValue(e.Value))
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// FormatLine renders a single KEY=value line without a trailing newline.
func FormatLine(key, value string) string { return key + "=" + QuoteValue(value) }

func isPlain(v string) bool {
	if v == "" {
		return true
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("_-./:@%+,=", r):
		default:
			return false
		}
	}
	return true
}

// QuoteValue picks the simplest representation: bare for plain values,
// single quotes (fully literal in most dotenv tools) when possible, and
// otherwise double quotes with escapes. '$' is escaped in double quotes so
// tools that do expand references leave it alone.
func QuoteValue(v string) string {
	if isPlain(v) {
		return v
	}
	if !strings.ContainsAny(v, "'\n\r") {
		return "'" + v + "'"
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '$':
			b.WriteString(`\$`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// WriteFile writes data to path atomically (temp file + rename in the same
// directory) with 0600 permissions. Without force it refuses to replace an
// existing file.
func WriteFile(path string, data []byte, force bool) (err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if info, statErr := os.Lstat(abs); statErr == nil {
		if !force {
			return fmt.Errorf("%w: %s (use --force to overwrite)", ErrExists, abs)
		}
		if info.IsDir() {
			return fmt.Errorf("%s is a directory", abs)
		}
	}
	dir := filepath.Dir(abs)
	tmp, err := os.CreateTemp(dir, ".ven-export-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	// CreateTemp already uses 0600 on Unix; Chmod is a no-op beyond the
	// read-only bit on Windows, where the user-profile ACL applies.
	if err = tmp.Chmod(0o600); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if !force {
		// Narrow the race between the existence check and the rename: a
		// hard link fails if the destination appeared in the meantime.
		if err = os.Link(tmpName, abs); err == nil {
			os.Remove(tmpName)
			return nil
		}
		if _, statErr := os.Lstat(abs); statErr == nil {
			return fmt.Errorf("%w: %s (use --force to overwrite)", ErrExists, abs)
		}
		// Filesystem without hard links: fall back to rename.
	}
	return os.Rename(tmpName, abs)
}
