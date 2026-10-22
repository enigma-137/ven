# Dotenv grammar

VEN parses dotenv input with its own small, documented grammar (`internal/envfile`). It never
executes anything, never performs command substitution and never expands references such as
`${OTHER}`. Anything outside this grammar is rejected with a line number rather than being
silently reinterpreted. Error messages may name a key but never include values.

## Input

- UTF-8 only; a leading UTF-8 BOM is ignored. Invalid UTF-8 is an error.
- CRLF (`\r\n`) line endings are accepted and treated as `\n`. A stray `\r` inside an unquoted
  value is an error.
- Maximum input size is 1 MiB; maximum value size is 64 KiB. NUL bytes are rejected.

## Lines

```
# comment                        whole-line comment (leading whitespace allowed)
                                 blank lines are ignored
KEY=value                        assignment
export KEY=value                 optional "export" prefix followed by spaces/tabs
KEY = value                      whitespace around "=" is allowed
```

**Keys** match `[A-Za-z_][A-Za-z0-9_.]*`, at most 256 characters. Keys must be unique within a
file: a duplicate key is an error that reports both line numbers.

## Values

| Form | Example | Result |
| --- | --- | --- |
| Empty | `KEY=` | empty string |
| Unquoted | `KEY=some value` | `some value` (surrounding whitespace trimmed) |
| Unquoted with `=` | `URL=a=b=c` | `a=b=c` |
| Unquoted with `#` | `COLOR=#fff`, `A=x#y` | `#fff`, `x#y` — `#` only starts a comment after whitespace |
| Inline comment | `KEY=value # note` | `value` |
| Single-quoted | `KEY='literal $HOME \n'` | exactly the characters between the quotes |
| Double-quoted | `KEY="a\tb \"c\""` | escapes processed (see below) |
| Multi-line | `KEY="line 1`⏎`line 2"` | quoted values may span lines (both quote styles) |

Rules:

- **Unquoted** values run to the end of the line. Whitespace followed by `#` starts a comment.
  Quote characters inside an unquoted value (`it's`) are kept literally.
- **Single-quoted** values are fully literal; they cannot contain `'`.
- **Double-quoted** values support exactly these escapes: `\n`, `\r`, `\t`, `\"`, `\\`, `\$`.
  Any other backslash escape is an error (so `"C:\Users"` must be written as `'C:\Users'` or
  `"C:\\Users"`).
- After a closing quote only whitespace and an optional `# comment` may follow.
- An unterminated quote is an error; parsing stops there because later lines cannot be trusted.
- Backtick-quoted values are rejected.
- `$VAR`, `${VAR}` and `$(cmd)` are stored **literally**. The import preview shows a warning for
  such values so it is clear nothing was expanded.

## Export format

Exports are canonical, not a copy of the original file:

1. A header comment warning that the file contains plaintext values.
2. One `KEY=value` line per variable, in display order.
3. Values are written bare when they only contain `A-Z a-z 0-9 _ - . / : @ % + , =`; otherwise in
   single quotes when they contain no `'` or line breaks; otherwise in double quotes with the
   escapes above (`$` is written as `\$` so tools that expand references leave it alone).

Every exported value parses back to exactly the same string with VEN (this is covered by unit
tests and fuzz tests). **Original comments, blank lines, ordering details and quoting style
are not preserved** in V1.

Other dotenv tools differ in their grammars. Bare and single-quoted output is read the same way
by most of them; double-quoted output relies on common escapes and may differ in tools that
treat `\$` or multi-line values differently.
