package envfile

import (
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func mustParse(t *testing.T, src string) map[string]string {
	t.Helper()
	r := Parse([]byte(src))
	if r.HasErrors() {
		t.Fatalf("unexpected errors: %v", r.Errors())
	}
	return r.Map()
}

func TestParseSupportedSyntax(t *testing.T) {
	src := "\ufeff# leading comment\n" +
		"\n" +
		"   \t\n" +
		"PLAIN=value\n" +
		"export EXPORTED=yes\n" +
		"EMPTY=\n" +
		"EMPTY_COMMENT= # nothing here\n" +
		"SPACED = padded value  \n" +
		"EQUALS=a=b=c\n" +
		"HASH=abc#def\n" +
		"INLINE=value # comment\n" +
		"SINGLE='literal $HOME \\n # not comment'\n" +
		"DOUBLE=\"tab\\there \\\"quoted\\\" back\\\\slash \\$NOT\"\n" +
		"QUOTED_COMMENT=\"x\" # trailing comment\n" +
		"UNICODE=héllo wörld 🎉\n" +
		"MULTI=\"line one\nline two\"\n" +
		"MULTI_SINGLE='a\nb'\n" +
		"dotted.key=1\n" +
		"CRLF=windows\r\n" +
		"APOSTROPHE=it's fine\n" +
		"LAST=no newline"
	got := mustParse(t, src)
	want := map[string]string{
		"PLAIN":          "value",
		"EXPORTED":       "yes",
		"EMPTY":          "",
		"EMPTY_COMMENT":  "",
		"SPACED":         "padded value",
		"EQUALS":         "a=b=c",
		"HASH":           "abc#def",
		"INLINE":         "value",
		"SINGLE":         `literal $HOME \n # not comment`,
		"DOUBLE":         "tab\there \"quoted\" back\\slash $NOT",
		"QUOTED_COMMENT": "x",
		"UNICODE":        "héllo wörld 🎉",
		"MULTI":          "line one\nline two",
		"MULTI_SINGLE":   "a\nb",
		"dotted.key":     "1",
		"CRLF":           "windows",
		"APOSTROPHE":     "it's fine",
		"LAST":           "no newline",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d entries, want %d", len(got), len(want))
	}
}

func TestParseNeverExpandsOrExecutes(t *testing.T) {
	r := Parse([]byte("A=${HOME}\nB=$(whoami)\nC=`id`\nD=\"$(rm -rf /)\"\n"))
	m := r.Map()
	if m["A"] != "${HOME}" || m["B"] != "$(whoami)" || m["D"] != "$(rm -rf /)" {
		t.Fatalf("values must be literal, got %q", m)
	}
	// Backtick values are rejected rather than reinterpreted.
	if !r.HasErrors() || r.Errors()[0].Line != 3 {
		t.Fatalf("expected an error on line 3 for backticks, got %v", r.Issues)
	}
	warnings := 0
	for _, i := range r.Issues {
		if i.Severity == SeverityWarning {
			warnings++
		}
	}
	if warnings != 3 {
		t.Fatalf("expected 3 reference warnings, got %v", r.Issues)
	}
}

func TestParseErrorsHaveLineNumbersAndNoValues(t *testing.T) {
	src := "GOOD=1\n" +
		"no equals sign here\n" + // 2
		"1BAD=supersecretvalue1\n" + // 3
		"=supersecretvalue2\n" + // 4
		"ESC=\"bad \\q supersecretvalue3\"\n" + // 5
		"TRAIL=\"x\" supersecretvalue4\n" + // 6
		"GOOD=again\n" + // 7 duplicate
		"OK2=fine\n" // 8
	r := Parse([]byte(src))
	lines := map[int]bool{}
	for _, i := range r.Errors() {
		lines[i.Line] = true
		if strings.Contains(i.Message, "supersecret") || strings.Contains(i.Message, "again") {
			t.Errorf("issue leaks value: %s", i.Message)
		}
	}
	for _, l := range []int{2, 3, 4, 5, 6, 7} {
		if !lines[l] {
			t.Errorf("expected error on line %d; got %v", l, r.Errors())
		}
	}
	if r.Map()["OK2"] != "fine" {
		t.Error("parsing should continue after recoverable errors")
	}
}

func TestParseUnterminatedQuote(t *testing.T) {
	r := Parse([]byte("A=1\nB=\"never closed\nC=3\n"))
	errs := r.Errors()
	if len(errs) != 1 || errs[0].Line != 2 || !strings.Contains(errs[0].Message, "unterminated") {
		t.Fatalf("got %v", errs)
	}
}

func TestParseRejectsInvalidUTF8AndNUL(t *testing.T) {
	if r := Parse([]byte("A=1\nB=\xff\xfe\n")); !r.HasErrors() || r.Errors()[0].Line != 2 {
		t.Fatalf("invalid UTF-8: %v", r.Issues)
	}
	if r := Parse([]byte("A=\"x\x00y\"\n")); !r.HasErrors() {
		t.Fatal("NUL byte should be rejected")
	}
}

func TestParseSizeLimit(t *testing.T) {
	if r := Parse(make([]byte, MaxFileSize+1)); !r.HasErrors() {
		t.Fatal("oversized input should be rejected")
	}
}

func TestDuplicateKeys(t *testing.T) {
	r := Parse([]byte("A=1\nB=2\nA=3\n"))
	errs := r.Errors()
	if len(errs) != 1 || errs[0].Line != 3 || !strings.Contains(errs[0].Message, "line 1") {
		t.Fatalf("got %v", errs)
	}
}

var roundTripValues = []string{
	"", "plain", "with space", " leading", "trailing ", "a=b", "#hash", "a #b",
	"it's", `"dq"`, "both ' and \"", "multi\nline", "cr\rlf", "crlf\r\n", "tab\tsep",
	`back\slash`, `trailing\`, "$HOME", "${VAR}", "$(cmd)", "`tick`", "'single'",
	"ünïcødé ✓", "emoji 🎉", "\\n literal", "line\n# not a comment", "=leading-equals",
	"export X=1", "\u00a0nbsp",
}

func TestSerializeRoundTrip(t *testing.T) {
	var entries []Entry
	for i, v := range roundTripValues {
		entries = append(entries, Entry{Key: "K" + strings.Repeat("_", i%3) + string(rune('A'+i%26)) + string(rune('A'+i/26)), Value: v})
	}
	out := Serialize(entries)
	r := Parse(out)
	if r.HasErrors() {
		t.Fatalf("reparse errors: %v\n%s", r.Errors(), out)
	}
	got := r.Map()
	for _, e := range entries {
		if got[e.Key] != e.Value {
			t.Errorf("%s: got %q, want %q", e.Key, got[e.Key], e.Value)
		}
	}
	if len(r.Entries) != len(entries) {
		t.Fatalf("got %d entries, want %d", len(r.Entries), len(entries))
	}
}

func TestWriteFileOverwriteProtection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := WriteFile(path, []byte("A=1\n"), false); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("A=2\n"), false); !errors.Is(err, ErrExists) {
		t.Fatalf("second write without force: got %v, want ErrExists", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "A=1\n" {
		t.Fatalf("file was modified: %q", b)
	}
	if err := WriteFile(path, []byte("A=2\n"), true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "A=2\n" {
		t.Fatalf("force write: %q", b)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
	if info, _ := os.Stat(path); os.PathSeparator == '/' && info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions = %v, want 0600", info.Mode().Perm())
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"A=1\n", "export B='x'\n", "C=\"a\\nb\"\n", "D=\"unterminated", "# c\n\nE= f # g\r\n", "=x", "F=`x`"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		r := Parse(src) // must not panic
		for _, i := range r.Issues {
			if i.Line < 0 {
				t.Fatalf("negative line number: %v", i)
			}
		}
		if r.HasErrors() {
			return
		}
		// Anything that parses cleanly must survive serialize → parse.
		again := Parse(Serialize(r.Entries))
		if again.HasErrors() {
			t.Fatalf("reparse failed: %v", again.Errors())
		}
		want, got := r.Map(), again.Map()
		for k, v := range want {
			if got[k] != v {
				t.Fatalf("%s: got %q, want %q", k, got[k], v)
			}
		}
	})
}

func FuzzQuoteValue(f *testing.F) {
	for _, v := range roundTripValues {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, v string) {
		if !utf8.ValidString(v) || strings.ContainsRune(v, 0) || len(v) > MaxValueSize {
			return
		}
		r := Parse([]byte(FormatLine("KEY", v) + "\n"))
		if r.HasErrors() {
			t.Fatalf("value %q: %v", v, r.Errors())
		}
		if got := r.Map()["KEY"]; got != v {
			t.Fatalf("got %q, want %q", got, v)
		}
	})
}

// TestParseRandomInputsTerminate is a cheap, deterministic complement to the
// fuzz targets: random inputs over the grammar's special characters must all
// parse (successfully or not) and round-trip when clean.
func TestParseRandomInputsTerminate(t *testing.T) {
	alphabet := []byte{'A', 'B', '=', '_', 39, '"', 92, ' ', 9, '#', 10, 13, '$', 96, 'x', 0xc3, 0xa9}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 50000; i++ {
		b := make([]byte, rng.Intn(40))
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		r := Parse(b)
		if r.HasErrors() {
			continue
		}
		again := Parse(Serialize(r.Entries))
		if again.HasErrors() || len(again.Entries) != len(r.Entries) {
			t.Fatalf("round trip failed for %q: %v", b, again.Issues)
		}
		for k, v := range r.Map() {
			if again.Map()[k] != v {
				t.Fatalf("round trip changed %s for input %q", k, b)
			}
		}
	}
}
