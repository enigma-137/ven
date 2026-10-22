# Architecture

VEN is one Go binary. The CLI and the dashboard server are two front ends over the same
application services; business logic lives in the service packages, not in Cobra commands or
HTTP handlers.

```
cmd/ven                      main: calls cli.Main
internal/cli                 Cobra commands, prompts, tables, exit codes
internal/server              loopback HTTP server: sessions, security middleware, JSON API, static files
web/                         React dashboard (Vite build → web/dist, embedded via web/embed.go)
        │                         │
        └──────────┬──────────────┘
                   ▼
internal/app                 wires one vault: opens storage, builds services; data-dir resolution; settings
internal/vault               master password, Argon2id, AES-256-GCM, key wrap/unwrap, in-memory Key
internal/projects            project CRUD, slug/name resolution, project setup with environments
internal/environments        environment CRUD within a project
internal/variables           encrypted variables, key-name classification, import plan/commit, export
internal/envfile             dotenv parser, canonical serializer, atomic 0600 file writer
internal/domain              validation errors, slugs, name rules
internal/storage             SQLite connection (pragmas, txlock), versioned migrations, row queries

V2 preview (hosted sharing):
internal/e2e                 end-to-end crypto: X25519 sealing, environment keys, account key wrap, invite/token secrets
internal/remote/api          JSON types shared by client and server
internal/remote/server       `ven server`: GitHub device login, sessions, projects, grants, invites, tokens, audit (own SQLite schema)
internal/remote/client       HTTP client and the saved login (account.json)
```

## Data flow

- **Unlocking**: `vault.Service.Unlock` reads `vault_config`, validates KDF bounds, derives the
  wrapping key with Argon2id and opens the wrapped data key. The result is a `*vault.Key` that
  can `Seal`/`Open` and is destroyed after use. The CLI holds it for one command; the server
  holds one per browser session until lock or auto-lock.
- **Variables**: `variables.Service` encrypts each value with the key and associated data built
  from the vault, project, environment and variable IDs, and stores ciphertext + nonce + format
  version. Listing returns metadata only; decrypting requires a key.
- **Import**: `envfile.Parse` → `variables.PlanImport` (decrypts existing values in memory only to
  classify keys as new/changed/unchanged/removed) → user decisions → `variables.ApplyImport`,
  which recomputes the plan inside one `BEGIN IMMEDIATE` transaction and rolls back on any error.
  Missing projects/environments are created only after confirmation and removed again if the
  import fails.
- **Export**: `variables.Export` decrypts in display order and `envfile.Serialize` writes canonical
  dotenv; the CLI writes it with `envfile.WriteFile` (temp file in the same directory, fsync,
  link/rename, 0600, refuses to overwrite without force).

## Database

SQLite via `modernc.org/sqlite` (pure Go). Each connection enables `foreign_keys`,
`busy_timeout=10000`, WAL, `synchronous=NORMAL` and `secure_delete`; transactions use
`BEGIN IMMEDIATE` so concurrent CLI and dashboard writers queue instead of failing.

Migrations are numbered SQL files in `internal/storage/migrations`, embedded in the binary and
applied in order inside transactions; applied versions are recorded in `schema_migrations`.
Add a new migration as `0002_description.sql`; never edit an applied one.

Tables: `vault_config` (singleton, encryption metadata), `settings`, `projects`,
`environments` (unique slug per project, cascade delete), `variables` (unique key per
environment, cascade delete, display type check, 12-byte nonce check). All queries are
parameterized.

## Decisions

- **IDs** are random 128-bit hex strings, so they are never reused and can be bound into
  associated data.
- **Slugs** follow names (renaming changes the slug) so CLI references stay intuitive.
- **Key names are not part of the associated data**: renaming a variable keeps its ciphertext
  valid because the record ID is what binds it.
- **Metadata is unencrypted** so listing and searching work without unlocking; see
  [security.md](security.md).
- **Duplicate keys in an imported file are an error**, not "last one wins", to avoid silent
  changes.
- **Non-interactive imports with conflicts fail** unless `--on-conflict` is given; replace mode
  always needs explicit confirmation.
- **Unknown key names default to `secret`** in the classifier; it only looks at the key name and
  never calls external services.
- **The dashboard requires an unlocked vault for all data**, including metadata, so a session that
  has auto-locked shows nothing.
- **Launch token in the URL fragment** rather than a query string, so it never reaches server logs
  or `Referer` headers.

## Frontend

`web/src`:

- `lib/api.ts` — typed fetch client; holds the CSRF token in memory; reports `locked` /
  `no_session` responses to the session provider.
- `lib/session.tsx` — bootstrap from the launch token, setup/locked/unlocked phases, idle
  detection, heartbeat, polling, and purge-on-lock (clears the query cache and remounts).
- `router.tsx` — TanStack Router routes: `/projects`, `/projects/$projectSlug?env=`, `/settings`.
- `pages/*` — Setup/Unlock, Projects, Project/Environment, Settings.
- `components/*` — layout, import dialog, variable dialog, confirmations, and `ui/` primitives in
  the shadcn/ui style (Radix Dialog/Tabs/Tooltip + Tailwind tokens from `index.css`).
