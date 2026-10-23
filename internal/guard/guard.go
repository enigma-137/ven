// Package guard finds secrets on their way into Git: .env files and values
// that VEN stores, wherever they are pasted.
//
// It never needs the vault password. VEN keeps a local index of salted
// HMAC-SHA256 fingerprints of secret values (not the values), refreshed
// whenever values are decrypted anyway (pull, import, set, export, or
// `ven guard index`). The scanner fingerprints each token of the scanned
// text and looks it up. Only secret-typed values of at least MinValueLen
// characters are indexed, so the fingerprints don't help anyone guess short
// or public values.
package guard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MinValueLen is the shortest value that is indexed.
const MinValueLen = 8

// maxValueLen bounds indexed values (longer ones are files, not tokens).
const maxValueLen = 4096

const formatVersion = 1

// Value is one secret to remember.
type Value struct {
	Name  string // variable key, for messages
	Value string
}

type entry struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
}

// Index is the on-disk fingerprint index (guard.json, 0600).
type Index struct {
	Version int                `json:"version"`
	Salt    []byte             `json:"salt"`
	Sources map[string][]entry `json:"sources"`

	path   string
	lookup map[string]Match
	lens   map[int]bool
}

// Match identifies which stored secret a token is.
type Match struct {
	Name   string
	Source string
}

// Load reads the index at path, creating an empty one if it is missing.
func Load(path string) (*Index, error) {
	ix := &Index{path: path}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		ix.Version = formatVersion
		ix.Sources = map[string][]entry{}
		if ix.Salt, err = randomSalt(); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, ix); err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		if ix.Version != formatVersion || len(ix.Salt) != 32 {
			return nil, fmt.Errorf("%s has an unsupported format; delete it and run ven guard index", path)
		}
		if ix.Sources == nil {
			ix.Sources = map[string][]entry{}
		}
	}
	ix.build()
	return ix, nil
}

func randomSalt() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

func (ix *Index) fingerprint(v string) string {
	m := hmac.New(sha256.New, ix.Salt)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

func (ix *Index) build() {
	ix.lookup = map[string]Match{}
	for src, list := range ix.Sources {
		for _, e := range list {
			ix.lookup[e.Hash] = Match{Name: e.Name, Source: src}
		}
	}
}

// Indexable reports whether a value is long enough to remember.
func Indexable(v string) bool {
	return len(v) >= MinValueLen && len(v) <= maxValueLen && !strings.ContainsAny(v, "\n\r")
}

// Replace sets the secrets known for one source (e.g. "local:api/development"
// or "hosted:octocat/api/production"), dropping what was there before.
func (ix *Index) Replace(source string, values []Value) {
	var list []entry
	seen := map[string]bool{}
	for _, v := range values {
		if !Indexable(v.Value) {
			continue
		}
		h := ix.fingerprint(v.Value)
		if seen[h] {
			continue
		}
		seen[h] = true
		list = append(list, entry{Name: v.Name, Hash: h})
	}
	if len(list) == 0 {
		delete(ix.Sources, source)
	} else {
		ix.Sources[source] = list
	}
	ix.build()
}

// Forget removes every source with the given prefix.
func (ix *Index) Forget(prefix string) {
	for src := range ix.Sources {
		if strings.HasPrefix(src, prefix) {
			delete(ix.Sources, src)
		}
	}
	ix.build()
}

// Len returns the number of remembered secrets.
func (ix *Index) Len() int { return len(ix.lookup) }

// SourceNames lists the sources, sorted.
func (ix *Index) SourceNames() []string {
	out := make([]string, 0, len(ix.Sources))
	for s := range ix.Sources {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Save writes the index atomically with 0600 permissions.
func (ix *Index) Save() error {
	b, err := json.Marshal(ix)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ix.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(ix.path), ".guard-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, os.ErrInvalid) {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), ix.path)
}

// tokenBreak lists characters that end a token. ':' and '/' are kept
// inside tokens so URLs with embedded credentials stay whole.
const tokenBreak = " \t\"'`=,;()[]{}<>|\\"

// hit is a stored secret found at line[Start:End].
type hit struct {
	Start, End int
	Match
}

// scanLine returns stored secrets appearing as whole tokens in line.
func (ix *Index) scanLine(line string) []hit {
	if len(ix.lookup) == 0 {
		return nil
	}
	var out []hit
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		tok := line[start:end]
		if Indexable(tok) {
			if m, ok := ix.lookup[ix.fingerprint(tok)]; ok {
				out = append(out, hit{Start: start, End: end, Match: m})
			} else if t := strings.TrimRight(tok, ".:"); t != tok && Indexable(t) {
				// Sentence punctuation after a value ("the key is X.").
				if m, ok := ix.lookup[ix.fingerprint(t)]; ok {
					out = append(out, hit{Start: start, End: start + len(t), Match: m})
				}
			}
		}
		start = -1
	}
	for i := 0; i < len(line); i++ {
		if strings.IndexByte(tokenBreak, line[i]) >= 0 {
			flush(i)
		} else if start < 0 {
			start = i
		}
	}
	flush(len(line))
	return out
}

// Mask shows a line with every hit replaced by a short prefix and dots.
func mask(line string, hits []hit) string {
	var b strings.Builder
	last := 0
	for _, h := range hits {
		b.WriteString(line[last:h.Start])
		v := line[h.Start:h.End]
		keep := min(4, len(v)/4)
		b.WriteString(v[:keep] + "•••••")
		last = h.End
	}
	b.WriteString(line[last:])
	s := strings.TrimSpace(b.String())
	if r := []rune(s); len(r) > 120 {
		s = string(r[:119]) + "…"
	}
	return s
}

// envTemplates are final name segments that mark a dotenv template, which
// is meant to be committed (.env.example, .env.local.sample).
var envTemplates = map[string]bool{"example": true, "sample": true, "template": true, "tmpl": true,
	"dist": true, "defaults": true, "default": true, "schema": true, "tpl": true}

// IsEnvFile reports whether a path names a dotenv file that should not be
// committed: .env, .env.local, .env.development.local, .env-local,
// .env_local, env.local and prod.env. Templates such as .env.example or
// .env.local.example are allowed. Other files (.envrc, config files) are
// still checked for stored secret values.
func IsEnvFile(path string) bool {
	base := strings.ToLower(filepath.Base(filepath.FromSlash(path)))
	if i := strings.LastIndexAny(base, "._-"); i >= 0 && envTemplates[base[i+1:]] {
		return false
	}
	switch {
	case base == ".env", base == "env.local":
		return true
	case strings.HasPrefix(base, ".env.") || strings.HasPrefix(base, ".env-") || strings.HasPrefix(base, ".env_"):
		return true
	case strings.HasPrefix(base, "env.") && strings.HasSuffix(base, ".local"):
		return true // env.development.local
	case strings.HasSuffix(base, ".env") && len(base) > len(".env"):
		return true
	}
	return false
}

// Finding is one problem the scanner reports.
type Finding struct {
	Kind    string // "env-file" or "secret"
	File    string
	Line    int    // 0 for env-file findings
	Commit  string // set when scanning history
	Name    string // variable name, for secrets
	Source  string // where VEN knows the secret from
	Preview string // masked line
}

// Kinds of findings.
const (
	KindEnvFile = "env-file"
	KindSecret  = "secret"
)

// ScanText scans whole file content (folder scans).
func (ix *Index) ScanText(file string, content []byte) []Finding {
	var out []Finding
	for i, line := range strings.Split(string(content), "\n") {
		if hits := ix.scanLine(line); len(hits) > 0 {
			out = append(out, findings(file, i+1, "", line, hits)...)
		}
	}
	return out
}

func findings(file string, line int, commit, text string, hits []hit) []Finding {
	preview := mask(text, hits)
	out := make([]Finding, 0, len(hits))
	for _, h := range hits {
		out = append(out, Finding{Kind: KindSecret, File: file, Line: line, Commit: commit, Name: h.Name, Source: h.Source, Preview: preview})
	}
	return out
}

// ScanDiff scans unified diff output (git diff -U0 or git log -p -U0),
// looking at added lines and at any added or changed .env file. Commit headers from
// `git log --format=%x00commit %H` set Finding.Commit.
func (ix *Index) ScanDiff(diff string) []Finding {
	var out []Finding
	var file, commit string
	line := 0
	for _, raw := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(raw, "\x00commit "):
			commit = strings.TrimSpace(strings.TrimPrefix(raw, "\x00commit "))
			if len(commit) > 12 {
				commit = commit[:12]
			}
			file = ""
		case strings.HasPrefix(raw, "diff --git "):
			file = ""
		case strings.HasPrefix(raw, "rename to "), strings.HasPrefix(raw, "copy to "):
			// Renames without content changes have no +++ line.
			p := strings.TrimPrefix(strings.TrimPrefix(raw, "rename to "), "copy to ")
			if p = unquote(p); IsEnvFile(p) && !hasEnvFinding(out, p, commit) {
				out = append(out, Finding{Kind: KindEnvFile, File: p, Commit: commit})
			}
		case strings.HasPrefix(raw, "+++ "):
			p := strings.TrimPrefix(raw, "+++ ")
			if p == "/dev/null" {
				file = ""
				continue
			}
			file = strings.TrimPrefix(unquote(p), "b/")
			if IsEnvFile(file) && !hasEnvFinding(out, file, commit) {
				out = append(out, Finding{Kind: KindEnvFile, File: file, Commit: commit})
			}
		case strings.HasPrefix(raw, "@@ "):
			line = hunkStart(raw)
		case strings.HasPrefix(raw, "+") && file != "":
			text := raw[1:]
			if !IsEnvFile(file) {
				if hits := ix.scanLine(text); len(hits) > 0 {
					out = append(out, findings(file, line, commit, text, hits)...)
				}
			}
			line++
		}
	}
	return out
}

func hasEnvFinding(list []Finding, file, commit string) bool {
	for _, f := range list {
		if f.Kind == KindEnvFile && f.File == file && f.Commit == commit {
			return true
		}
	}
	return false
}

// hunkStart parses "@@ -a,b +c,d @@" and returns c.
func hunkStart(h string) int {
	i := strings.Index(h, " +")
	if i < 0 {
		return 0
	}
	rest := h[i+2:]
	n := 0
	for _, r := range rest {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// unquote strips Git's C-style quoting of unusual paths ("b/odd name").
func unquote(p string) string {
	if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
		return strings.ReplaceAll(p[1:len(p)-1], `\"`, `"`)
	}
	return p
}
