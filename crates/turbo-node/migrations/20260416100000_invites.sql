-- Invite tokens (user-stories.md §8.1).
--
-- `invite_id` is the raw 16-byte token id (hex-encoded by callers, but the
-- storage uses the same BLOB convention as `entries.tenant_id`).
-- `secret_hash` is SHA-256(invite_secret); the raw secret is never stored,
-- so a DB dump cannot redeem pending invites.
-- `hostnames_json` is a JSON array of pre-approved hostname patterns. JSON
-- is the path of least resistance for a list column in SQLite, and we only
-- ever read it back as a whole.
-- `tenant_id` is populated on redemption (32-byte Ed25519 public key).
-- `expires_at_ms` and timestamps are unix milliseconds (protocol §1).
CREATE TABLE invites (
    invite_id      BLOB NOT NULL PRIMARY KEY,
    name           TEXT NOT NULL,
    hostnames_json TEXT NOT NULL,
    secret_hash    BLOB NOT NULL,
    expires_at_ms  INTEGER NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'redeemed', 'revoked')),
    tenant_id      BLOB,
    redeemed_at_ms INTEGER,
    created_at_ms  INTEGER NOT NULL
);
