# VEN

VEN is an open-source, local vault for environment variables. It lets you import, organize,
edit, copy and export `.env` values across projects and environments, from a Go CLI or a
local web dashboard. Both use the same Go services, database layer, dotenv parser and
encryption code.

> **Status: V1, unreviewed.** VEN has not had an external security review. Do not treat
> it as audited or production-secure. Read [docs/security.md](docs/security.md) for the threat
> model and limitations before storing real credentials.

- Single user, single local vault, no accounts, no network services beyond `127.0.0.1`.
- Every value is encrypted with AES-256-GCM under a random vault key; the vault key is
  wrapped with a key derived from your master password (Argon2id).
- There is **no password recovery** in V1.

## Contents

- [Install](#install) · [Build from source](#build-from-source)
- [Quick start](#quick-start)
- [CLI reference](#cli-reference)
- [Dashboard](#dashboard)
- [Hosted projects and teams (V2 preview)](#hosted-projects-and-teams-v2-preview)
- [Where data lives](#where-data-lives)
- [Development](#development)
- [Dependencies](#dependencies)
- Docs: [architecture](docs/architecture.md) · [dotenv grammar](docs/dotenv.md) ·
  [security model](docs/security.md) · [roadmap](ROADMAP.md) · [contributing](CONTRIBUTING.md) ·
  [reporting vulnerabilities](SECURITY.md) · [licensing](LICENSING.md)

Licensed under the [Apache License 2.0](LICENSE).

## Install

**Linux / macOS:**

```bash
curl -fsSL https://raw.githubusercontent.com/enigma-137/ven/HEAD/scripts/install.sh | sh
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/enigma-137/ven/HEAD/scripts/install.ps1 | iex
```

Both scripts download the latest [release](https://github.com/enigma-137/ven/releases/latest),
check its SHA-256 checksum and install `ven` to `~/.local/bin` (Windows:
`%LOCALAPPDATA%\Programs\ven`, added to your PATH). You can also download an archive from the
releases page yourself. The binaries are not code-signed yet, so Windows SmartScreen may warn on
first run, and macOS may block an archive opened in Finder (the install script avoids that).

### Releasing

Push a version tag; GitHub Actions tests, builds Linux/macOS/Windows (amd64 and arm64) with the
dashboard embedded, and publishes the release with checksums:

```bash
git tag v0.2.0 && git push origin v0.2.0
```

## Build from source

Requirements: Go 1.26+ and Node.js 20.19+ or 22.12+ (Node is only needed to build the dashboard). No C
compiler is needed; the SQLite driver is pure Go.

```bash
make build                 # builds web/dist, then bin/ven with the dashboard embedded
```

On Windows without `make`:

```powershell
.\scripts\build.ps1        # same as make build, produces bin\ven.exe
```

Go-only build (the dashboard shows a "not built" page if `web/dist` is empty):

```bash
go build -o bin/ven ./cmd/ven
```

## Quick start

```bash
ven init                                    # choose a master password (min. 10 characters)
ven projects create "Billing API"           # creates development, staging, production
ven import .env --project billing-api --env development
ven list --project billing-api --env development
ven get STRIPE_SECRET_KEY -p billing-api -e development
ven export -p billing-api -e development --out .env
ven ui                                      # open the dashboard
```

Every command that reads or writes values asks for the master password with hidden input.
Commands that only touch metadata (`projects`, `envs`, `list`, `unset`, `status`) work
without it, because names are stored unencrypted (see [security](docs/security.md)).

## CLI reference

Run `ven <command> --help` for full help. Global flags:

| Flag | Meaning |
| --- | --- |
| `--vault <path>` | Use a specific vault file (also `$VEN_VAULT`). Handy for testing. |
| `--non-interactive` | Never prompt; fail with exit code 6 if input is needed. |
| `--password-stdin` | Read the master password from the first line of stdin (scripts). |
| `--no-color` | Disable colors (also honours `NO_COLOR`). |

| Command | Description |
| --- | --- |
| `ven init` | Create the vault and master password. |
| `ven status` | Vault path, state, KDF parameters, schema version. |
| `ven projects list` | List projects. |
| `ven projects create <name> [--description d] [--envs a,b,c]` | Create a project (default environments: development, staging, production; `--envs ""` for none). |
| `ven projects rename <project> <name>` | Rename (the slug follows the name). |
| `ven projects update <project> --description d` | Change the description. |
| `ven projects delete <project> [--yes]` | Delete, after typing the slug to confirm. |
| `ven envs list\|create\|rename\|delete --project <p>` | Manage environments. |
| `ven import <file> -p <p> -e <e> [--replace] [--on-conflict overwrite\|keep] [--create] [--dry-run] [--type KEY=text] [--yes]` | Preview and import a dotenv file. |
| `ven export [-p <p> -e <e>] [--out .env] [--force] [--stdout]` | Export an environment. |
| `ven list -p <p> -e <e> [--search s]` | Keys, types and metadata; values masked. |
| `ven get <KEY> -p <p> -e <e>` | Print one plaintext value to stdout. |
| `ven set <KEY> -p <p> -e <e> [--type secret\|text] [--description d] [--value-stdin]` | Create or update; the value is read with hidden input. |
| `ven unset <KEY> -p <p> -e <e>` | Delete a variable. |
| `ven password change` | Change the master password. |
| `ven ui [--port 7420] [--no-browser]` | Start the dashboard on 127.0.0.1. |
| `ven version` | Print the version. |

`<project>` and `<environment>` accept a slug or a name.

### Import

```bash
ven import .env -p api -e development                 # merge (default)
ven import .env.prod -p api -e production --replace   # remove keys not in the file
ven import .env -p api -e staging --on-conflict keep --non-interactive
ven import .env -p new-app -e dev --create            # create missing project/environment
```

VEN shows a preview table (`new`, `changed`, `unchanged`, `removed`) before writing. Malformed
lines are reported with their line numbers and never echo values. Conflicts (`changed`) are
resolved interactively (overwrite all / keep all / per key) or with `--on-conflict`. Replace
mode requires typing `replace` (or `--yes`). The import is committed in a single transaction.

### Export

```bash
ven export                                            # interactive selection, writes ./.env
ven export -p api -e development --out .env --force   # overwrite an existing file
ven export -p api -e staging --stdout | some-tool     # stdout only carries the dotenv data
```

Exports contain **plaintext** values. Files are written atomically with `0600` permissions on
Unix-like systems (on Windows the user-profile ACLs apply) and are never overwritten without
`--force` or an interactive confirmation. Prompts and diagnostics always go to stderr.

### Scripting

```bash
printf '%s\n' "$MASTER" | ven --password-stdin get API_TOKEN -p api -e dev
printf '%s\n%s' "$MASTER" "$VALUE" | ven --password-stdin set API_TOKEN -p api -e dev --value-stdin
```

Exit codes: `0` ok, `1` error, `2` usage/validation, `3` not initialized or wrong password,
`4` not found, `5` conflict / destination exists / unresolved import conflicts,
`6` input required in non-interactive mode, `130` cancelled.

## Dashboard

```bash
ven ui
```

`ven ui` binds `127.0.0.1:7420` (or a free port if busy), prints a link containing a one-time
launch token in the URL fragment, and opens your browser. The dashboard covers setup/unlock,
projects, environments, the variable table (reveal, copy value, copy `KEY=value`, copy all,
edit, delete), import (upload, drag and drop or paste, with preview and conflict choices),
export download and settings (vault location, auto-lock interval, password change, lock).

The dashboard auto-locks after inactivity (default 15 minutes, configurable) and when the
server stops. Stop it with Ctrl+C.

## Hosted projects and teams (V2 preview)

> **Preview, unreviewed.** Everything above works offline without an account. The commands
> below are optional and talk to a VEN server (`ven server`, self-hostable; see
> [deploy/README.md](deploy/README.md)). Design and threat model: [docs/v2-design.md](docs/v2-design.md).

Hosted projects are **end-to-end encrypted**: values are encrypted on your machine, the server
stores only ciphertext and cannot read values, variable names, private keys or invite secrets.
GitHub login says *who you are*; your **account password** unlocks your key and never leaves
your machine.

```bash
ven login --server https://ven.example.com     # GitHub device login; first time: choose an account password
ven remote create "Billing API"                # owner/billing-api with development, staging, production
ven link billing-api -e development            # writes .ven.json (no secrets)
ven push --from .env                           # encrypt and upload (shows added/changed/removed keys)
ven pull                                       # decrypt into .env
ven run -- npm run dev                         # inject variables into one process, nothing on disk
eval "$(ven shellenv)"                         # export into the current shell (PowerShell: ven shellenv | iex)
ven copy STRIPE_SECRET_KEY                     # one value to the clipboard
```

Sharing with a teammate:

```bash
ven share --to octocat --env development,staging --role developer   # prints a ven_inv_… code
#   teammate:  ven login && ven join ven_inv_…
ven members                                    # who has access, until when
ven members approve octocat                    # grant a protected env (production) after comparing fingerprints
ven members renew octocat --for 30d            # access expires after 30 days by default
ven members remove octocat --yes               # revoke and rotate the keys they had
ven tokens create --name ci --env production   # read-only token: VEN_SERVER=… VEN_TOKEN=ven_st_… ven run -- ./deploy.sh
ven audit                                      # who pulled, pushed, shared, approved
```

An invite code only works for the named GitHub account, only once, and expires after 24 hours.
Production-like environments are **protected**: the code alone never unlocks them.

| Command | Description |
| --- | --- |
| `ven login [--server URL]` / `logout` / `whoami` | Log in with GitHub, revoke the session, show your key fingerprint. |
| `ven remote list\|create\|publish\|envs create\|rotate\|delete` | Manage hosted projects; `publish` uploads a local project. |
| `ven link <project> -e <env>` | Remember the project/environment for this directory. |
| `ven pull [--out f] [--stdout]` / `push [--from f] [--merge]` | Download/upload an environment. |
| `ven run -- <cmd>` / `shellenv [--shell posix\|fish\|powershell]` / `copy [KEY]` | Use variables without a file. |
| `ven share` / `join` / `invites [revoke]` | Invite people, accept invites, manage pending ones. |
| `ven members [remove\|renew\|role\|approve]` | Manage access. |
| `ven tokens [create\|revoke]` | Read-only service tokens for CI and servers. |
| `ven audit` | Project audit log (admins). |
| `ven server` | Run the server (see [deploy/README.md](deploy/README.md)). |

## Where data lives

| OS | Default vault |
| --- | --- |
| Windows | `%AppData%\VEN\vault.db` |
| macOS | `~/Library/Application Support/VEN/vault.db` |
| Linux | `$XDG_DATA_HOME/ven/vault.db` or `~/.local/share/ven/vault.db` |

If you use hosted projects, the login is kept in `account.json` (0600) in the same directory.

Override with `--vault` or `VEN_VAULT`. Back up the `.db` file (and its `-wal` file if
present, or stop VEN first). A backup is only useful with the master password.

## Development

```bash
go test ./...                 # Go tests (temporary vaults, dummy values only)
go vet ./...
make fuzz                     # dotenv parser fuzzing (30 s per target)
npm --prefix web ci
npm --prefix web run typecheck
npm --prefix web run build
```

Frontend dev server with hot reload:

```bash
ven ui --port 7420 --no-browser --vault ./dev.db   # terminal 1, copy the launch token
npm --prefix web run dev                            # terminal 2
# open http://127.0.0.1:5173/#launch=<token>
```

Vite proxies `/api` to the Go server and rewrites `Origin`, so the server's checks still apply.

### Platform support

Verified: Windows 11 (amd64) — the Go test suite, the CLI and the dashboard were exercised there.
The code cross-compiles for Linux and macOS (amd64/arm64), but those platforms have **not** been
run or tested yet.

## Dependencies

Kept deliberately small:

| Dependency | Why |
| --- | --- |
| `spf13/cobra` | CLI commands, flags and help. |
| `modernc.org/sqlite` | Maintained SQLite driver in pure Go: no CGO, so cross-compiling and Windows builds need no C toolchain. |
| `golang.org/x/crypto/argon2` | Argon2id key derivation. AES-256-GCM comes from the Go standard library. |
| `golang.org/x/term` | Hidden password input. |
| React, TypeScript, Vite | Dashboard UI and build. |
| TanStack Query / Router | Server state (memory-only, never persisted) and type-safe routing. |
| Tailwind CSS | Styling via design tokens in `web/src/index.css`. |
| Radix UI (dialog, tabs, tooltip) | Accessible primitives; components are written in the shadcn/ui style in `web/src/components/ui`. |
| lucide-react | A few icons for copy, reveal, edit and navigation. |
| clsx, tailwind-merge | Class name helpers (shadcn's `cn`). |

The frontend is compiled into `web/dist` and embedded with `go:embed`; no third-party scripts
or fonts are loaded at runtime.
