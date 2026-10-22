# Contributing to VEN

Thanks for helping. VEN handles credentials, so changes are held to a careful standard.

## Setup

Requirements: Go 1.26+, Node.js 20.19+ or 22.12+. No C compiler is needed.

```bash
git clone <your fork>
cd ven
npm --prefix web ci
make check          # go vet, go test, frontend type check and build
make build          # bin/ven with the embedded dashboard
```

Windows without make: `.\scripts\build.ps1 -Check` and `.\scripts\build.ps1`.

Use a throwaway vault while developing: `ven --vault ./dev.db ...` or `VEN_VAULT=./dev.db`.

## Ground rules

- **Never use real credentials** in tests, fixtures, screenshots, issues or examples. Use
  obviously fake values (`dummy`, `sk_test_dummy`).
- Never log values, imported contents, passwords or keys — including in error messages.
  Error messages may name keys and line numbers.
- Keep business logic in the service packages (`internal/vault`, `projects`, `environments`,
  `variables`, `envfile`). CLI commands and HTTP handlers should stay thin.
- Use parameterized SQL and transactions. Schema changes go in a **new** numbered migration in
  `internal/storage/migrations`; never edit an existing one.
- Do not add cryptographic primitives or change the encryption format without a design
  discussion in an issue first. Format changes need a version bump in the associated data.
- Keep dependencies few. Explain any new dependency in the pull request and in the README table.
- Security-relevant changes (crypto, sessions, origin/host checks, CSP) need tests.

## Tests

```bash
go test ./...
make fuzz                         # dotenv fuzzers, 30 s each
npm --prefix web run typecheck
```

Tests create temporary vaults with reduced (but in-bounds) Argon2id parameters for speed.
Please add tests with your change: unit tests for services, `internal/cli/cli_test.go` for CLI
workflows (it uses a scripted fake terminal) and `internal/server/server_test.go` for the API.

## Code style

- Go: `gofmt`, `go vet`, small packages, comments for anything non-obvious.
- TypeScript: strict mode; match the existing component patterns; keep text values rendered as
  text (no `dangerouslySetInnerHTML`); never put values in URLs or web storage.
- UI: follow the design tokens in `web/src/index.css`; icon-only buttons need an accessible label
  and tooltip.

## Pull requests

Describe what changed and why, how you tested it, and any security implications. Report
vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in a pull request.
