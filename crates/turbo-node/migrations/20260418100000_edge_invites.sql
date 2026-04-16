-- Edge-node invites (user-stories.md §5).
--
-- Same invariants as the tenant `invites` table: `secret_hash` is
-- SHA-256(secret); the raw secret never hits disk. `edge_node_id` is the
-- iroh EndpointId (Ed25519 pubkey) the redeeming operator registers.
CREATE TABLE edge_invites (
    invite_id       BLOB NOT NULL PRIMARY KEY,
    name            TEXT NOT NULL,
    secret_hash     BLOB NOT NULL,
    expires_at_ms   INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'redeemed', 'revoked')),
    edge_node_id    BLOB,
    redeemed_at_ms  INTEGER,
    created_at_ms   INTEGER NOT NULL
);

-- Edges registered via redeemed edge-invites. Authoritative list of
-- iroh node_ids that are allowed to subscribe to `/v1/routes/subscribe`.
CREATE TABLE edges (
    edge_node_id     BLOB NOT NULL PRIMARY KEY,
    name             TEXT NOT NULL,
    registered_at_ms INTEGER NOT NULL
);
