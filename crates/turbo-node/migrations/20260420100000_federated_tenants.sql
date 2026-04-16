-- Tenants this hub learned about from a peer hub via federation
-- (POST /v1/federation/tenants). Distinct from `invites` (locally
-- redeemed) and `tenant_removals` (locally evicted) — federated tenants
-- exist *because* a peer told us so. At hub boot they are merged into
-- the in-memory OwnershipPolicy alongside static + redeemed - removed.
--
-- `source_peer_node_id` records which peer first announced the tenant,
-- for audit. If a tenant arrives from multiple peers the first writer
-- wins (PRIMARY KEY conflict on tenant_id).
CREATE TABLE federated_tenants (
    tenant_id           BLOB NOT NULL PRIMARY KEY,
    pq_public_key       BLOB NOT NULL,
    hostnames_json      TEXT NOT NULL,
    registered_at_ms    INTEGER NOT NULL,
    source_peer_node_id BLOB NOT NULL
);
