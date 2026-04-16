-- Operator-driven tenant removals (user-stories.md §6.2).
--
-- When the operator runs `turbo-cli tenant remove`, we don't delete the
-- tenant's signed entries (they stay cryptographically valid) and we don't
-- touch the invite they came in through. We just record that this tenant
-- is no longer welcome. At boot the hub filters both the static TOML
-- allowlist and the redeemed-invite-derived allowlist through this table.
--
-- Re-admission (a future command) is a DELETE on this table; the tenant's
-- old signed entries become active again automatically.
CREATE TABLE tenant_removals (
    tenant_id      BLOB NOT NULL PRIMARY KEY,
    removed_at_ms  INTEGER NOT NULL
);
