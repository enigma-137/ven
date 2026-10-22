-- 0002_recovery: optional recovery key for the vault.
--
-- A second, independent wrap of the same vault data key, under a key derived
-- (HKDF-SHA256) from a random 160-bit recovery key that is shown to the user
-- once and never stored. Either the master password or the recovery key can
-- unlock the data key.

CREATE TABLE vault_recovery (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    salt        BLOB NOT NULL CHECK (length(salt) = 16),
    nonce       BLOB NOT NULL CHECK (length(nonce) = 12),
    wrapped_key BLOB NOT NULL,
    created_at  TEXT NOT NULL
);
