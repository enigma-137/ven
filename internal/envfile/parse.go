// Package envfile parses and writes dotenv files using VEN's documented
// grammar (see docs/dotenv.md). Parsing never executes, expands or
// substitutes anything: values are taken literally.
package envfile

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxFileSize is the largest dotenv input accepted (1 MiB).
const MaxFileSize = 1 << 20

// MaxValueSize is the largest single value accepted (64 KiB).
const MaxValueSize = 64 << 10

// MaxKeyLength is the longest accepted key.
const MaxKeyLength = 256

var keyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

// ValidKey reports whether k is an acceptable variable key.
func ValidKey(k string) bool {
	return len(k) <= MaxKeyLength && keyPattern.MatchString(k)
}

// KeyRule describes the key grammar for error messages.
const KeyRule = "keys must start with a letter or underscore and contain only letters, digits, underscores and dots"

// Entry is one parsed KEY=value assignment.
type Entry struct {
	Key   string
	Value string
	Line  int // 1-based line where the assignment starts
}

// Severity of a parse issue.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Issue is a parse problem. Messages may name keys but never include values.
type Issue struct {
	Line     int      `json:"line"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

func (i Issue) String() string { return fmt.Sprintf("line %d: %s: %s", i.Line, i.Severity, i.Message) }

// Result is the outcome of parsing.
type Result struct {
	Entries []Entry
	Issues  []Issue
}

// HasErrors reports whether any error-severity issue was found.
func (r *Result) HasErrors() bool { return len(r.Errors()) > 0 }

// Errors returns only error-severity issues.
func (r *Result) Errors() []Issue {
	var out []Issue
	for _, i := range r.Issues {
		if i.Severity == SeverityError {
			out = append(out, i)
		}
	}
	return out
}

// Map returns entries as a key→value map (only meaningful without errors).
func (r *Result) Map() map[string]string {
	m := make(map[string]string, len(r.Entries))
	for _, e := range r.Entries {
		m[e.Key] = e.Value
	}
	return m
}

type parser struct {
	src  []byte
	pos  int
	line int
	res  *Result
}

func (p *parser) errorf(line int, format string, args ...any) {
	p.res.Issues = append(p.res.Issues, Issue{Line: line, Severity: SeverityError, Message: fmt.Sprintf(format, args...)})
}

func (p *parser) warnf(line int, format string, args ...any) {
	p.res.Issues = append(p.res.Issues, Issue{Line: line, Severity: SeverityWarning, Message: fmt.Sprintf(format, args...)})
}

// Parse parses dotenv content. It always returns a Result; callers must
// check HasErrors before using the entries.
func Parse(src []byte) *Result {
	res := &Result{}
	if len(src) > MaxFileSize {
		res.Issues = append(res.Issues, Issue{Severity: SeverityError, Message: fmt.Sprintf("input is larger than %d bytes", MaxFileSize)})
		return res
	}
	src = bytes.TrimPrefix(src, []byte("\xef\xbb\xbf"))
	src = bytes.ReplaceAll(src, []byte("\r\n"), []byte("\n"))

	if !utf8.Valid(src) {
		res.Issues = append(res.Issues, Issue{Line: firstInvalidUTF8Line(src), Severity: SeverityError, Message: "input is not valid UTF-8"})
		return res
	}

	p := &parser{src: src, line: 1, res: res}
	p.run()
	p.checkDuplicates()
	return res
}

func firstInvalidUTF8Line(src []byte) int {
	line := 1
	for i := 0; i < len(src); {
		r, size := utf8.DecodeRune(src[i:])
		if r == utf8.RuneError && size <= 1 {
			break
		}
		if src[i] == '\n' {
			line++
		}
		i += size
	}
	return line
}

func (p *parser) run() {
	for p.pos < len(p.src) {
		raw := p.restOfLine()
		trimmed := strings.Trim(raw, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos += len(raw)
			p.nextLine()
			continue
		}
		if !p.parseAssignment(p.line) {
			return // unterminated quote: nothing after it can be trusted
		}
	}
}

// nextLine consumes the newline at pos, if any.
func (p *parser) nextLine() {
	if p.pos < len(p.src) && p.src[p.pos] == '\n' {
		p.pos++
	}
	p.line++
}

// restOfLine returns the bytes from pos to end of line (exclusive).
func (p *parser) restOfLine() string {
	end := bytes.IndexByte(p.src[p.pos:], '\n')
	if end < 0 {
		return string(p.src[p.pos:])
	}
	return string(p.src[p.pos : p.pos+end])
}

func (p *parser) skipBlanks() {
	for p.pos < len(p.src) && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t') {
		p.pos++
	}
}

// skipLine records nothing and moves to the start of the next line.
func (p *parser) skipLine() {
	p.pos += len(p.restOfLine())
	p.nextLine()
}

// parseAssignment parses one assignment starting at line. It returns false
// when parsing cannot continue.
func (p *parser) parseAssignment(line int) bool {
	p.skipBlanks()
	rest := p.restOfLine()

	if strings.HasPrefix(rest, "export") && len(rest) > 6 && (rest[6] == ' ' || rest[6] == '\t') {
		p.pos += 6
		p.skipBlanks()
		rest = p.restOfLine()
	}

	eq := strings.IndexByte(rest, '=')
	if eq < 0 {
		p.errorf(line, "expected KEY=value (missing '=')")
		p.skipLine()
		return true
	}
	key := strings.TrimRight(rest[:eq], " \t")
	if !ValidKey(key) {
		switch {
		case key == "":
			p.errorf(line, "missing key before '='")
		case len(key) > MaxKeyLength:
			p.errorf(line, "key is longer than %d characters", MaxKeyLength)
		default:
			p.errorf(line, "invalid key: %s", KeyRule)
		}
		p.skipLine()
		return true
	}
	p.pos += eq + 1
	p.skipBlanks()

	var value string
	if p.pos < len(p.src) {
		switch c := p.src[p.pos]; c {
		case '\'', '"':
			v, st := p.quoted(c, line, key)
			switch st {
			case quoteFatal:
				return false
			case quoteSkip:
				p.nextLine()
				return true
			}
			value = v
		case '`':
			p.errorf(line, "%s: backtick-quoted values are not supported", key)
			p.skipLine()
			return true
		default:
			v, ok := p.unquoted(line, key)
			if !ok {
				p.nextLine()
				return true
			}
			value = v
		}
	}
	p.nextLine()

	if len(value) > MaxValueSize {
		p.errorf(line, "%s: value is larger than %d bytes", key, MaxValueSize)
		return true
	}
	if strings.ContainsRune(value, 0) {
		p.errorf(line, "%s: value contains a NUL byte", key)
		return true
	}
	if referencePattern.MatchString(value) {
		p.warnf(line, "%s: value contains '$' syntax; VEN stores it literally and never expands references or runs commands", key)
	}
	p.res.Entries = append(p.res.Entries, Entry{Key: key, Value: value, Line: line})
	return true
}

var referencePattern = regexp.MustCompile(`\$[A-Za-z_{(]`)

// unquoted reads an unquoted value up to end of line. Whitespace followed by
// '#' begins an inline comment; surrounding whitespace is trimmed.
func (p *parser) unquoted(line int, key string) (string, bool) {
	rest := p.restOfLine()
	p.pos += len(rest)
	value := rest
	precededByBlank := len(p.src) > 0 && p.pos-len(rest) > 0 &&
		(p.src[p.pos-len(rest)-1] == ' ' || p.src[p.pos-len(rest)-1] == '\t')
	if strings.HasPrefix(rest, "#") && precededByBlank {
		value = ""
	}
	for i := 1; i < len(value); i++ {
		if value[i] == '#' && (value[i-1] == ' ' || value[i-1] == '\t') {
			value = value[:i]
			break
		}
	}
	value = strings.TrimRight(value, " \t")
	if strings.ContainsRune(value, '\r') {
		p.errorf(line, "%s: unexpected carriage return in unquoted value", key)
		return "", false
	}
	return value, true
}

type quoteStatus int

const (
	quoteOK    quoteStatus = iota
	quoteSkip              // error recorded; pos is at end of a line
	quoteFatal             // unterminated; stop parsing
)

// quoted reads a single- or double-quoted value which may span lines. On
// return pos is at the end of the line holding the closing quote.
func (p *parser) quoted(q byte, line int, key string) (string, quoteStatus) {
	p.pos++ // opening quote
	var b strings.Builder
	for {
		if p.pos >= len(p.src) {
			p.errorf(line, "%s: unterminated %s-quoted value", key, quoteName(q))
			return "", quoteFatal
		}
		c := p.src[p.pos]
		switch {
		case c == q:
			p.pos++
			p.skipBlanks()
			tail := p.restOfLine()
			p.pos += len(tail)
			if tail != "" && !strings.HasPrefix(tail, "#") {
				p.errorf(p.line, "%s: unexpected characters after closing quote", key)
				return "", quoteSkip
			}
			return b.String(), quoteOK
		case c == '\n':
			b.WriteByte('\n')
			p.pos++
			p.line++
		case c == '\\' && q == '"':
			if p.pos+1 >= len(p.src) {
				p.errorf(line, "%s: unterminated double-quoted value", key)
				return "", quoteFatal
			}
			switch e := p.src[p.pos+1]; e {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '"', '\\', '$':
				b.WriteByte(e)
			default:
				p.errorf(p.line, `%s: unsupported escape sequence in double-quoted value (supported: \n \r \t \" \\ \$)`, key)
				return "", p.skipToClosingQuote(q, line, key)
			}
			p.pos += 2
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
}

// skipToClosingQuote moves past the closing quote after an error so later
// lines can still be checked.
func (p *parser) skipToClosingQuote(q byte, line int, key string) quoteStatus {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == '\\' && q == '"' && p.pos+1 < len(p.src) {
			if p.src[p.pos+1] == '\n' {
				p.line++
			}
			p.pos += 2
			continue
		}
		if c == '\n' {
			p.line++
		}
		p.pos++
		if c == q {
			p.pos += len(p.restOfLine())
			return quoteSkip
		}
	}
	p.errorf(line, "%s: unterminated %s-quoted value", key, quoteName(q))
	return quoteFatal
}

func quoteName(q byte) string {
	if q == '\'' {
		return "single"
	}
	return "double"
}

func (p *parser) checkDuplicates() {
	first := map[string]int{}
	for _, e := range p.res.Entries {
		if l, ok := first[e.Key]; ok {
			p.errorf(e.Line, "duplicate key %s (first defined on line %d)", e.Key, l)
			continue
		}
		first[e.Key] = e.Line
	}
}
