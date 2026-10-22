# V2 design: accounts, teams and sharing from the terminal

> **Status: build steps 1–5 implemented, unreviewed.** `ven server`, GitHub login, hosted
> projects, sharing, approvals, rotation, service tokens and the audit log exist in the code
> (`internal/e2e`, `internal/remote`, `internal/cli`). Dashboard pages (step 6) and Google login
> do not exist yet. Where the implementation differs from the original proposal, §12 says so.

V1 is a local vault for one person. V2 adds what the [roadmap](../ROADMAP.md) lists under
accounts, teams and sharing, with one goal: a teammate can get a project's variables into their
terminal without opening the dashboard, and **a leaked token, a hacked GitHub account or a
compromised server on its own never exposes a secret.**

## 1. GitHub login or a password? Both, for different jobs

| | Job | What it protects against |
| --- | --- | --- |
| **GitHub or Google login** (OAuth) | Proves *who you are* to the VEN server: which account, which projects, which role. No VEN passwords to store, reset or leak; GitHub's own 2FA applies. | Someone using your invite or token without being you. |
| **Master password** (as in V1) | Unlocks *your private key*, which is what actually decrypts values. Never leaves your machine. | A stolen GitHub session, a stolen laptop disk, or a breached VEN server. |

GitHub alone is not enough: if the server could decrypt values for anyone with a valid GitHub
session, then a phished GitHub account or a server breach would expose every team's secrets.
The password alone is not enough either: it cannot tell the server which person is asking, and
we do not want to run our own account system with resets and MFA.

So V2 is **end-to-end encrypted**: the server stores ciphertext, membership and audit records,
and cannot read values. Decryption only happens in the CLI or the dashboard, on the user's
machine.

## 2. Keys, in one picture

```
your master password ──Argon2id──▶ wraps your private key (X25519, generated on your device)
                                         │
project key (random 256-bit, one per environment) ──wrapped to each member's public key──┐
                                         │                                                │
variable values ◀──AES-256-GCM── environment key                       stored on the server
```

- Each user has one X25519 key pair, created at `ven login` on their first device. The public
  key goes to the server; the private key is stored on the server **only** wrapped with the
  master password (same Argon2id parameters and bounds as V1), so a second device can fetch it.
- Each **environment** has its own random key. Values are encrypted under it exactly like V1
  (AES-256-GCM, associated data binding the record IDs).
- Giving someone access to an environment = wrapping that environment's key to their public key
  (X25519 → HKDF-SHA256 → AES-256-GCM). Access to `development` never implies `production`.
- Removing someone = the server stops serving them ciphertext **and** we rotate the environment
  key (new key, re-encrypt values, re-wrap for remaining members). See §6 for the limit of this.

All primitives come from the Go standard library (`crypto/ecdh`, `crypto/hkdf`,
`crypto/aes`/`cipher`) plus the Argon2id already used in V1. No home-made crypto.

## 3. Team access: invite → login → join → pull

The flow you described ("I add you, you authenticate, I give you a key, you pull the env"),
made safe against the key leaking:

```bash
# Owner
ven share billing-api --to octocat --env development,staging --role developer   # access lasts 30 days by default
#   ✓ Invite for @octocat (expires in 24 h, single use):
#     ven_inv_8f2c…        ← send this over Slack, email, whatever

# Teammate
ven login                  # GitHub device flow: opens github.com/login/device, enter code
ven join ven_inv_8f2c…     # asks for their master password, accepts the invite
ven pull                   # writes .env for the linked project/environment
```

What makes the invite code safe to paste into chat:

1. **Bound to one GitHub account.** The invite is for `@octocat`. Anyone else who uses it,
   even with the full code, is refused by the server.
2. **Single use and short-lived.** It works once and expires after 24 h by default
   (`--invite-ttl`). Unused invites can be revoked: `ven invites revoke`.
3. **It carries a secret the server never sees.** The code is `id + secret`. The owner's CLI
   wraps the environment keys under a key derived from `secret` and uploads only that blob; the
   server stores a hash of the `id` to find it. On `ven join`, the teammate's CLI unwraps the
   environment keys with `secret`, re-wraps them to the teammate's own public key, and the
   server deletes the invite blob. The server alone can never open it.
4. **Access itself expires.** Memberships last 30 days by default (`--expires` to change,
   `ven members renew` to extend), separate from the invite's own 24 h limit. After that the server stops serving ciphertext and VEN rotates the keys.

Required for `production`, optional elsewhere (`--approve`): the owner confirms the join
(`ven members approve octocat`) and shows both sides a short key fingerprint to compare, which
defends against a compromised server substituting its own public key.

### Roles

| Role | Can |
| --- | --- |
| `viewer` | Pull the environments they were given. |
| `developer` | Viewer + set/unset/import variables in those environments. |
| `admin` | Developer + invite, remove, change roles, create environments. |
| `owner` | Admin + delete or transfer the project. One or more per project. |

Roles are always per environment set, so "developer on development and staging, nothing on
production" is the normal case.

## 4. Getting variables into your terminal

A project is linked once per directory; afterwards no flags are needed.

```bash
ven link billing-api --env development   # writes .ven.json: {"project":"billing-api","env":"development"}
                                         # (no secrets; safe to commit, and VEN adds .env to .gitignore if missing)

ven pull                     # decrypt and write ./.env (0600, shows a diff, asks before overwriting)
ven pull --stdout            # print dotenv to stdout, for pipes
ven copy                     # copy the whole env (KEY=value lines) to the clipboard
ven copy STRIPE_SECRET_KEY   # copy one value
ven shellenv                 # print `export KEY='value'` lines:  eval "$(ven shellenv)"
ven run -- npm run dev       # inject variables into one process, nothing written to disk
```

`ven run` is the recommended default because no plaintext `.env` file is left lying around;
`ven pull` exists because many tools still expect a file. `ven push` (the reverse of pull)
uploads local changes for users with the `developer` role, with the same preview/conflict
screen as `ven import`.

## 5. Tokens for CI and servers

Teammates are people with GitHub accounts. CI jobs and servers get **service tokens** instead:

```bash
ven tokens create billing-api --env production --name github-actions --expires 90d --read-only
#   ven_st_3a91…   (shown once)

# in CI
VEN_TOKEN=ven_st_3a91… ven run -- ./deploy.sh
```

Like invites, a service token contains a secret that unwraps a copy of the environment key, so
the server still cannot decrypt. Tokens are scoped to one project and listed environments,
read-only unless stated, must have an expiry (max 1 year), can be restricted by IP range later,
show "last used" in `ven tokens list`, and are revoked with `ven tokens revoke`. They cannot
invite people or create other tokens.

## 6. What a leak costs, honestly

| What leaks | Result |
| --- | --- |
| An invite code | Nothing, unless the attacker is also logged in as the invited GitHub user before it is used or expires. |
| A GitHub account | Attacker can see project names and membership, not values: they still need the master password. Owner removes them and the keys rotate. |
| The VEN server database | Ciphertext, wrapped keys and metadata. No values without users' passwords. Weak passwords can be guessed offline, slowly (Argon2id). |
| A service token | Read access to its environments until revoked or expired. Revoke it and rotate the affected values at their source (Stripe, AWS, …). |
| A teammate who leaves | Revoking stops future access and rotates VEN's keys, but **anything they already pulled they still know.** VEN will list the variables they accessed (`ven audit --member octocat`) so you know what to rotate at the provider. No tool can un-share a secret. |

## 7. Other security pieces

- **Audit log**: every pull, push, copy, join, invite, token use and role change, with user,
  time and IP. Viewable with `ven audit` and in the dashboard. The log never contains values.
- **CLI sessions**: `ven login` stores a short-lived access token (1 h) and a refresh token
  (30 days, rotated on use) in the OS keychain, never in a plain file. `ven logout` revokes both.
- **Unlocking**: the master password is asked per command as in V1; optional keychain caching
  for N minutes (roadmap item) for people who pull often.
- **Recovery**: an optional recovery key printed at first login (a second wrap of your private
  key). Losing both password and recovery key means re-joining projects, not losing team data,
  because other members still hold the environment keys.
- **Server**: TLS only, rate limits on login/join/token endpoints, invite and token secrets
  compared in constant time and stored hashed, and an external security review before anything
  is called production-ready.

## 8. Local vault stays

Local-only use from V1 keeps working without an account. `ven login` is opt-in, and
`ven projects publish billing-api` uploads an existing local project to the server (encrypting
its environments under new keys) so you can start sharing it.

## 9. Suggested build order

1. **Server skeleton** (`ven server`, SQLite) + GitHub login with the device flow for the CLI
   and normal OAuth for the dashboard. Google login follows the same interface.
2. **User keys**: key pair at first login, wrapped private key, second-device login.
3. **Hosted projects**: publish, pull, push, `ven link`, `ven run`, `ven shellenv`, `ven copy`.
4. **Sharing**: invites, join, roles, expiry, revoke + key rotation, audit log.
5. **Service tokens** and a GitHub Actions example.
6. Dashboard pages for members, invites, tokens and audit; then external review.

## 10. Decisions

| # | Question | Decision | Why |
| --- | --- | --- | --- |
| 1 | Hosting | **`ven server` is part of the same binary and anyone can self-host it. We run one small hosted instance ourselves.** The server uses **SQLite** (as in V1), not Postgres, until load proves otherwise. | The server only stores ciphertext and membership, so it is light: one small VPS (a few dollars a month) or a free/low tier on a container host is enough to start. Self-hosting costs us nothing and lets security-minded teams keep data in-house. Billing, if ever, comes later. |
| 2 | Login providers | **GitHub first, Google second.** GitLab only if users ask. | GitHub covers most developers. Google covers everyone else, and its basic `openid email profile` sign-in needs no paid verification and supports a terminal flow. Invites are bound to a GitHub username or a Google email address. |
| 3 | Membership expiry | **30 days by default, renewable** (`ven members renew octocat --for 30d`). `--expires never` must be stated explicitly and is admin-only. Service tokens: 90 days by default, 1 year maximum. | Forgotten access ends on its own. Renewing is one command, and VEN warns owners 5 days before expiry. |
| 4 | Fingerprint check | **Required for `production` environments, optional elsewhere.** | Production is where a swapped key would hurt most. Comparing a short code (six groups of four characters) once per teammate is cheap. It is CLI code only, with no running cost. |

## 11. Deployment (first hosted instance)

Target: the existing Interserver VPS that also runs TraceIQ (Ubuntu 26.04, 1 vCPU, 3.3 GiB RAM,
~40 GB free disk, checked 2026-10-22). VEN's footprint is expected to be tens of MB of RAM and
well under 1 GB of disk. The server does no Argon2id work, because password-based key wrapping
happens on users' machines, so one vCPU is enough.

| Item | Value |
| --- | --- |
| Folder | `/home/traceiq/ven` (`0700`), database in `/home/traceiq/ven/data` (`0700`, file `0600`) |
| Listen address | `127.0.0.1:4100` (TraceIQ uses 4000/4001; Caddy admin is 2019) |
| Public access | Through the existing Caddy on 80/443, which handles TLS; VEN never listens on a public interface |
| Process | systemd unit running as `traceiq`, `Restart=on-failure`, hardened with `NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths=/home/traceiq/ven/data`, `PrivateTmp`, and a memory cap so VEN can never starve TraceIQ |
| Secrets | GitHub/Google OAuth client secrets in `/home/traceiq/ven/env` (`0600`), loaded by systemd, never in the repo |
| Backups | Nightly `sqlite3 .backup` into `/home/traceiq/ven/backups`, keeping the last 14, copied off the VPS. Backups hold only ciphertext |
| Domain | To be decided (e.g. `ven.<your-domain>`), DNS A record → the VPS |

Caddy site block, added next to TraceIQ's and not replacing it:

```
ven.example.com {
    reverse_proxy 127.0.0.1:4100
    header Strict-Transport-Security "max-age=31536000; includeSubDomains"
}
```

The unit file, Caddy snippet and backup script will be committed under `deploy/` together with
the server code in build step 1.

## 12. Implementation notes (differences from the proposal)

- **Command names**: `ven env` already meant `ven envs` in V1, so the shell-export command is
  `ven shellenv`. Hosted project management lives under `ven remote` (`list`, `create`,
  `publish`, `envs create`, `rotate`, `delete`); everyday commands are top level (`login`,
  `logout`, `whoami`, `link`, `pull`, `push`, `run`, `shellenv`, `copy`, `share`, `join`,
  `members`, `invites`, `tokens`, `audit`).
- **One encrypted blob per environment**: the server stores each environment's whole dotenv
  content as a single ciphertext with a revision number, not one row per variable. So the
  server cannot see variable *names* either, and pushes are atomic with optimistic
  concurrency (a push based on an old revision is refused). The audit log therefore records
  "pulled revision N" rather than per-variable reads.
- **Invites, tokens and users are all key holders**: every principal has an X25519 public key.
  For invites and tokens the private key is derived from the secret inside the code/token.
  Rotation re-seals the new environment key to all of them, so service tokens and pending
  invites keep working after a teammate is removed; revoked ones simply are not re-sealed.
- **Rotation is client-side**: the server flags an environment `needs_rotation` when a member
  or token loses access (removal, expiry, revocation) and refuses new pushes until it is
  rotated. `ven members remove` and `ven tokens revoke` rotate immediately; otherwise the next
  `pull`/`push`/`run` by a developer or admin with access does it automatically.
- **Session storage**: the CLI keeps the login in `account.json` (0600) next to the local vault,
  not in the OS keychain yet. Access tokens last 1 h; refresh tokens 30 days, single use, and
  reusing an old one ends the session on every device.
- **Clipboard**: `ven copy` does not clear the clipboard automatically.
- **Default role** for `ven share` is `viewer` (least privilege); pass `--role developer` to let
  someone push.
- **Account password** is separate from the local vault's master password (you may choose the
  same one). Creating projects and joining only need your public key; decrypting needs the
  password.
- **Account recovery key**: the first `ven login` also prints a recovery key (`VENA-…`), a
  second wrap of the account private key (HKDF-SHA256 + AES-256-GCM, bound to the user ID and
  public key) stored with the password wrap. `ven account recover` sets a new account password
  and keeps all access; `ven account recovery-key` replaces it. Re-uploading a wrap of the same
  public key is allowed, because nobody can produce a valid wrap without holding the key.
- **Forgotten account password and lost recovery key**: `ven login --reset-key` replaces the account key. The server
  deletes every environment key sealed to the old one and flags those environments for
  rotation, so the reset never grants access; admins share with the user again (protected
  environments still need an approval showing the new fingerprint). Recorded in each project's
  audit log as `member.key_reset`.
- **Default server**: `ven login` uses `https://ven.traceiq.run` unless `--server`, `$VEN_SERVER`
  or a previous login says otherwise.
