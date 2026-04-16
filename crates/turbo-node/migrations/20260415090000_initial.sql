-- Initial schema: signed config entries persisted by the hub.
--
-- `tenant_id` is a raw 32-byte Ed25519 public key. `signature` is a raw
-- 64-byte Ed25519 signature. `payload_cbor` is the exact canonical CBOR
-- bytes that were signed (see docs/protocol.md §3.4).
--
-- PRIMARY KEY (tenant_id, sequence) enforces monotonic, non-replayable
-- entries per tenant at the storage layer.
CREATE TABLE entries (
    tenant_id    BLOB NOT NULL,
    sequence     INTEGER NOT NULL,
    payload_cbor BLOB NOT NULL,
    signature    BLOB NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (tenant_id, sequence)
);
