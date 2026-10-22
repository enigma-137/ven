# Security model and limitations

> The optional hosted features (V2 preview: `ven server`, login, sharing) have their own
> threat model in [v2-design.md](v2-design.md) §6–7 and §12. This document covers the local
> vault and dashboard.

VEN V1 is a local, single-user tool. This document describes what it protects, how, and what
it does not protect. **VEN has not been externally reviewed or audited.**

## What VEN aims to protect against

- Someone who obtains a copy of the vault file (backup, stolen disk image, synced folder)
  without the master password should not be able to read variable values.
- Tampering with stored ciphertext or encryption metadata should be detected, not silently
  produce wrong values.
- Web pages in your browser should not be able to read or change the vault through the local
  dashboard (CSRF, DNS rebinding, cross-origin reads).
- Values should not leak into logs, error messages, URLs, browser storage or metadata API
  responses.

## Out of scope

- Malware, keyloggers or anyone controlling your unlocked machine or user account. While a CLI
  command or dashboard session is unlocked, the key is in process memory.
- Other processes running as your user. They can read the vault file, talk to the loopback
  server, and read the terminal output of `ven ui` (including the launch link).
- Plaintext you export: `.env` files, `--stdout` output, clipboard contents, browser downloads.
- Weak or reused master passwords. Argon2id slows guessing; it cannot make a weak password strong.
- Integrity of unencrypted metadata (names, structure) against someone who can write the file.

## Cryptography

| Item | Choice |
| --- | --- |
| Vault data key | 256 random bits from `crypto/rand`, generated once at `ven init`. |
| Key wrapping | AES-256-GCM with a key derived by Argon2id from the master password. |
| KDF | Argon2id v1.3, **m = 64 MiB, t = 3, p = 4**, 16-byte random salt (RFC 9106 "second recommended" option). Parameters and salt are stored with the wrapped key. |
| KDF bounds | Stored parameters are only accepted within m 8 MiB–1 GiB, t 1–10, p 1–16, salt 16–64 bytes, so a tampered file cannot force extreme resource use or trivially weak settings. |
| Value encryption | AES-256-GCM (Go standard library), a fresh random 96-bit nonce from `crypto/rand` for every encryption. Values are re-encrypted with a new nonce on every write. |
| Associated data (values) | Versioned and length-prefixed: label `ven/variable-value`, format version, vault ID, project ID, environment ID, variable ID. Moving a ciphertext to another record, environment, project or vault fails authentication. |
| Associated data (vault key) | Label `ven/vault-key`, format version, vault ID, KDF algorithm/version/parameters and salt. Editing KDF metadata makes unlock fail. |
| Password change | Verifies the current password, derives a new wrapping key with a **new salt**, re-wraps the same data key. Stored values are untouched. |
| Master password policy | At least 10 characters, valid UTF-8, at most 1024 bytes. |

With random 96-bit nonces, the chance of a nonce repeating under one key stays negligible for
far more encryptions than a personal vault will perform (the usual guidance is to stay well
below 2³² messages per key). VEN does not implement its own primitives.

### What is encrypted and what is not

Encrypted: **every variable value**, regardless of its display type (`secret` or `text`), and
the vault data key.

**Not encrypted** (readable by anyone with the file):

- project names, slugs and descriptions
- environment names and slugs
- variable keys (names), display types, descriptions and sort order
- created/updated timestamps, counts, the vault ID
- KDF parameters, salt and nonces (these are not secret)
- dashboard settings (auto-lock interval)

Choose names and descriptions with that in mind. This is why metadata commands such as
`ven list` work without the password.

## Local storage

- The vault is a SQLite database in the per-user data directory (see README). On Unix-like
  systems the directory is created `0700` and the database file `0600`; SQLite's `-wal`/`-shm`
  sidecar files follow your umask, which is why the directory permissions matter. On Windows,
  the user profile's ACLs apply.
- SQLite runs with foreign keys on, a 10 s busy timeout, WAL journaling and `BEGIN IMMEDIATE`
  transactions so the CLI and dashboard can be used concurrently. `secure_delete` is enabled so
  deleted ciphertext is overwritten in the database file (WAL files and filesystem snapshots
  may still hold old pages).
- Plaintext values and keys are never written to SQLite, temporary files or configuration.
- Imports are committed in a single transaction; failures roll back completely.

## CLI

- The master password and values are read with hidden terminal input or from stdin
  (`--password-stdin`, `--value-stdin`). They are never accepted as command-line arguments.
- Each invocation unlocks independently; there is no background daemon or cached key.
- `ven get` and `ven export --stdout` print plaintext by design. Prompts and diagnostics go to
  stderr. Parse errors report line numbers, never values.
- Ctrl+C restores the terminal and exits; database writes are transactional.

## Local dashboard

- Binds to `127.0.0.1` only.
- **Host validation**: requests must carry `Host: 127.0.0.1:<port>`, `localhost:<port>` or
  `[::1]:<port>`; anything else gets `421`. This blocks DNS-rebinding attacks.
- **Session bootstrap**: `ven ui` prints a link with a random 256-bit launch token in the URL
  fragment (fragments are never sent to servers or written to server logs). The page sends it
  once to `POST /api/session`, removes it from the address bar and keeps it in memory only.
  Failed attempts are throttled.
- **Session cookie**: random 256-bit ID, `HttpOnly`, `SameSite=Strict`, `Path=/`, no
  persistence. `Secure` is not set because the dashboard is plain HTTP on loopback. Sessions end
  after 2 h without requests, after 12 h in total, or when the server stops.
- **CSRF**: every API request except session bootstrap/status needs an `X-CSRF-Token` header
  matching the session (held in page memory only), including reads, so a leaked cookie alone is
  not enough.
- **Origin checks**: state-changing requests need an `Origin` header equal to the dashboard's
  own origin; requests whose `Sec-Fetch-Site` is `cross-site` or `same-site` are refused. No CORS
  headers are ever sent.
- **Unlock throttling**: password checks are serialized; after 5 consecutive failures each
  attempt waits 2^(n−5) s (capped at 5 min), returned as `429` with `Retry-After`.
- **Auto-lock**: the server destroys the in-memory key after the configured inactivity
  interval (1–240 min, default 15). Activity is user interaction reported by the page's
  heartbeat and API calls; status polling does not count. A background sweep enforces this even
  without requests. Every protected request re-checks lock state on the server.
- **Responses**: metadata endpoints never include values. Secret values are only returned by
  explicit reveal/copy/edit/export actions (`POST` + CSRF). Text-typed values are returned for
  display while unlocked. All API responses carry `Cache-Control: no-store`.
- **Limits**: 64 KiB request bodies (4 MiB for import requests, with decoded content capped at
  1 MiB), header and read timeouts, at most 32 concurrent sessions.
- **Headers**: `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self' data:; font-src 'self'; connect-src 'self'; ...; frame-ancestors 'none'`, plus
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy`. The frontend is embedded in
  the binary; no third-party scripts, styles or fonts are loaded.
  Known effect of the strict `style-src`: the dialog library's scroll-lock `<style>` element is
  blocked, so the page behind an open dialog can still scroll. This is cosmetic.

### Frontend handling

- TanStack Query data lives in memory only (no persister) with short cache lifetimes.
- Revealed secrets are kept in the table row's component state and hide after 30 s; edit dialogs
  fetch the value when opened and clear it when closed.
- On lock, auto-lock or an expired-session response, the page cancels queries, clears the query
  cache and remounts the app, discarding component state.
- Nothing is written to `localStorage`, `sessionStorage` or URLs other than project/environment
  slugs. Imported content is rendered as text, never as HTML.
- The export dialog warns that downloaded files are plaintext.

## Memory

VEN wipes key material and password buffers after use where it controls them (best effort).
Go strings are immutable and the garbage collector may copy memory, and browsers keep their
own copies of anything displayed or fetched, so **complete erasure of secrets from memory
cannot be guaranteed** in either runtime.

## No recovery

There is no recovery key or reset in V1. If you forget the master password, the values cannot
be decrypted. Recovery-key workflows are on the [roadmap](../ROADMAP.md).
