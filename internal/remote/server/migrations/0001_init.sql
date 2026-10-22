-- 0001_init: hosted VEN server schema.
--
-- The server stores ciphertext only: environment content and environment
-- keys are encrypted on clients (internal/e2e). Private keys are stored
-- wrapped with the user's account password. Invite and token secrets are
-- never stored; only SHA-256 hashes of keys derived from them.

CREATE TABLE users (
    id                  TEXT PRIMARY KEY,
    provider            TEXT NOT NULL,
    provider_user_id    TEXT NOT NULL,
    handle              TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (length(handle) BETWEEN 1 AND 100),
    name                TEXT NOT NULL DEFAULT '',
    public_key          BLOB CHECK (public_key IS NULL OR length(public_key) = 32),
    wrapped_private_key TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    UNIQUE (provider, provider_user_id)
);

CREATE TABLE sessions (
    id                 TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    access_hash        BLOB NOT NULL UNIQUE,
    access_expires_at  TEXT NOT NULL,
    refresh_hash       BLOB NOT NULL UNIQUE,
    prev_refresh_hash  BLOB,
    refresh_expires_at TEXT NOT NULL,
    user_agent         TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL,
    last_used_at       TEXT NOT NULL
);

CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_prev_refresh_idx ON sessions (prev_refresh_hash);

CREATE TABLE projects (
    id         TEXT PRIMARY KEY,
    owner_id   TEXT NOT NULL REFERENCES users (id),
    name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    slug       TEXT NOT NULL CHECK (length(slug) BETWEEN 1 AND 64),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (owner_id, slug)
);

CREATE TABLE environments (
    id             TEXT PRIMARY KEY,
    project_id     TEXT    NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    name           TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    slug           TEXT    NOT NULL CHECK (length(slug) BETWEEN 1 AND 64),
    protected      INTEGER NOT NULL DEFAULT 0,
    key_version    INTEGER NOT NULL DEFAULT 1,
    revision       INTEGER NOT NULL DEFAULT 0,
    content_nonce  BLOB,
    content        BLOB,
    needs_rotation INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT    NOT NULL,
    updated_at     TEXT    NOT NULL,
    UNIQUE (project_id, slug)
);

CREATE TABLE members (
    project_id TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('viewer', 'developer', 'admin', 'owner')),
    expires_at TEXT,
    added_by   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, user_id)
);

CREATE INDEX members_user_idx ON members (user_id);

CREATE TABLE invites (
    id                TEXT PRIMARY KEY,
    project_id        TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    provider          TEXT NOT NULL,
    handle            TEXT NOT NULL COLLATE NOCASE,
    user_id           TEXT REFERENCES users (id) ON DELETE CASCADE,
    role              TEXT NOT NULL CHECK (role IN ('viewer', 'developer', 'admin')),
    public_key        BLOB NOT NULL CHECK (length(public_key) = 32),
    auth_hash         BLOB NOT NULL CHECK (length(auth_hash) = 32),
    member_expires_at TEXT,
    expires_at        TEXT NOT NULL,
    created_by        TEXT NOT NULL,
    created_at        TEXT NOT NULL
);

CREATE TABLE tokens (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    name         TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    public_key   BLOB NOT NULL CHECK (length(public_key) = 32),
    auth_hash    BLOB NOT NULL CHECK (length(auth_hash) = 32),
    expires_at   TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_used_at TEXT
);

-- grants: who holds which environment key. sealed_key is NULL while a
-- protected environment waits for approval.
CREATE TABLE grants (
    environment_id TEXT    NOT NULL REFERENCES environments (id) ON DELETE CASCADE,
    principal_type TEXT    NOT NULL CHECK (principal_type IN ('user', 'invite', 'token')),
    principal_id   TEXT    NOT NULL,
    key_version    INTEGER NOT NULL,
    sealed_key     BLOB,
    created_at     TEXT    NOT NULL,
    PRIMARY KEY (environment_id, principal_type, principal_id)
);

CREATE INDEX grants_principal_idx ON grants (principal_type, principal_id);

-- audit outlives projects on purpose (no foreign key).
CREATE TABLE audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    ip          TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE INDEX audit_project_idx ON audit (project_id, id);
