-- 0001_init: initial VEN schema.
--
-- Unencrypted by design: project/environment names, slugs and descriptions,
-- variable keys, display types, descriptions, sort order and timestamps.
-- Encrypted: every variable value (AES-256-GCM) and the vault data key
-- (wrapped with an Argon2id-derived key).

CREATE TABLE vault_config (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    vault_id          TEXT    NOT NULL,
    format_version    INTEGER NOT NULL,
    kdf_algorithm     TEXT    NOT NULL CHECK (kdf_algorithm = 'argon2id'),
    kdf_version       INTEGER NOT NULL,
    kdf_memory_kib    INTEGER NOT NULL CHECK (kdf_memory_kib > 0),
    kdf_iterations    INTEGER NOT NULL CHECK (kdf_iterations > 0),
    kdf_parallelism   INTEGER NOT NULL CHECK (kdf_parallelism > 0),
    kdf_salt          BLOB    NOT NULL,
    wrapped_key_nonce BLOB    NOT NULL,
    wrapped_key       BLOB    NOT NULL,
    created_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE projects (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    slug        TEXT NOT NULL UNIQUE CHECK (length(slug) BETWEEN 1 AND 64),
    description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE environments (
    id         TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    slug       TEXT NOT NULL CHECK (length(slug) BETWEEN 1 AND 64),
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (project_id, slug)
);

CREATE INDEX environments_project_idx ON environments (project_id);

CREATE TABLE variables (
    id               TEXT PRIMARY KEY,
    environment_id   TEXT    NOT NULL REFERENCES environments (id) ON DELETE CASCADE,
    key              TEXT    NOT NULL CHECK (length(key) BETWEEN 1 AND 256),
    value_ciphertext BLOB    NOT NULL,
    value_nonce      BLOB    NOT NULL CHECK (length(value_nonce) = 12),
    enc_version      INTEGER NOT NULL,
    display_type     TEXT    NOT NULL CHECK (display_type IN ('secret', 'text')),
    description      TEXT    NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    sort_order       INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL,
    UNIQUE (environment_id, key)
);

CREATE INDEX variables_environment_idx ON variables (environment_id);
