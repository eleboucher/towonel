# Config simplification: `TOWONEL_DATA_DIR` and cascading defaults

**Date:** 2026-05-19
**Status:** Approved (brainstorm)
**Owner:** Erwan Leboucher

## Problem

A self-hosted deployment currently needs ~17 `TOWONEL_*` env vars to boot a
node, of which most either restate the existing default or paste a path under
`/data`. Operators copy boilerplate from the README and frequently get one
wrong (e.g. forgetting `TOWONEL_HUB_OPERATOR_API_KEY_PATH`, ending up with a
key file in the container's cwd).

Concrete pain in `docker-compose.yml` setups: paths like `node.key`,
`hub.db`, `operator.key` default to relative cwd locations, which on a
typical image-with-volume layout is the wrong directory and silently writes
state where it won't survive a restart.

## Goal

Reduce required env vars to the genuinely deployment-specific ones, **without
breaking any existing deployment** that already pins them explicitly.

After this change a minimal docker-compose stanza for the common
"behind-a-reverse-proxy" deployment shape needs:

- `TOWONEL_HUB_PUBLIC_URL` — public HTTPS URL of the hub
- `TOWONEL_EDGE_TLS_ACME_EMAIL` — Let's Encrypt account email (when ACME is on)
- `TOWONEL_INVITE_HASH_KEY` *or* auto-gen to file under `${DATA_DIR}`

Optional reverse-proxy port overrides remain available but are unchanged.

## Non-goals

- Bundling Caddy into the node image (deferred — separate project).
- Reading config from a YAML/TOML file (deferred — env-only stays).
- Renaming or deprecating any existing env var.

## Design

### New env var: `TOWONEL_DATA_DIR`

- Type: `Option<PathBuf>`
- Default: `None` (behavior identical to today)
- When set: supplies defaults for every path-shaped env var the node reads.
- Docker images set `ENV TOWONEL_DATA_DIR=/data` in `Dockerfile.node` so
  compose users get the cascade automatically.

### Cascading defaults

When `TOWONEL_DATA_DIR=${D}` is set **and** the per-var env var is unset:

| Env var | Today's default | New default (DATA_DIR set) |
|---|---|---|
| `TOWONEL_IDENTITY_KEY_PATH` | none (error) | `${D}/node.key` |
| `TOWONEL_HUB_DB_DSN` (sqlite) | `hub.db` (cwd) | `${D}/hub.db` |
| `TOWONEL_HUB_OPERATOR_API_KEY_PATH` | `operator.key` (cwd) | `${D}/operator.key` |
| `TOWONEL_EDGE_TLS_CERT_DIR` | `/data/certs` (only if any TLS env set) | `${D}/certs` |
| `TOWONEL_INVITE_HASH_KEY_PATH` (new) | n/a | `${D}/invite_hash.key` |

`TOWONEL_HUB_DB_DSN` cascade applies only to the sqlite driver. Postgres
deployments still require a full DSN — there is nothing meaningful to derive
from a directory.

### `TOWONEL_EDGE_PUBLIC_ADDRESSES` derivation

If `TOWONEL_EDGE_PUBLIC_ADDRESSES` is unset **and** `TOWONEL_HUB_PUBLIC_URL`
is set, default to `<host-of-hub-public-url>:443`. Single-DNS deployments
where the hub and edge share a hostname need not declare it twice.

Multi-DNS operators (hub on `hub.example.com`, edge on
`tunnel.example.com`) override explicitly — same as today.

### `TOWONEL_INVITE_HASH_KEY` becomes optional

New env var: `TOWONEL_INVITE_HASH_KEY_PATH` (default `${DATA_DIR}/invite_hash.key`
when `DATA_DIR` is set, otherwise unset).

Resolution order at hub startup:

1. If `TOWONEL_INVITE_HASH_KEY` (env) is set → parse and use (today's behavior).
2. Else if `TOWONEL_INVITE_HASH_KEY_PATH` is set:
   - If the file exists → read, parse, use.
   - If the file does not exist → generate 32 random bytes, hex-encode,
     write 0o600, log `WARN: generated new invite-hash key at <path> — back
     it up; losing it invalidates every outstanding invite`.
3. Else → keep today's error message (asking operator to set the env var or
   run `openssl rand -hex 32`).

This mirrors the existing `load_or_generate_operator_key` flow in
`crates/towonel-node/src/hub/mod.rs:49`. Production deployments that pin
the env var keep working unchanged; greenfield docker-compose deploys
boot with zero secret-management ceremony.

### Identity-source resolution (already nearly correct)

Today: error if neither `TOWONEL_IDENTITY_KEY_PATH` nor
`TOWONEL_EDGE_INVITE_TOKEN` is set.

New order, in `config.rs::from_raw`:
1. If `TOWONEL_EDGE_INVITE_TOKEN` set → derive seed (unchanged).
2. Else if `TOWONEL_IDENTITY_KEY_PATH` set → use it (unchanged).
3. Else if `TOWONEL_DATA_DIR` set → use `${DATA_DIR}/node.key` (new).
4. Else → existing error message (unchanged).

### Dockerfile change

In `Dockerfile.node`, add `ENV TOWONEL_DATA_DIR=/data`. No change needed in
`Dockerfile.agent` — the agent's config does not consume data-dir paths.

### Updated docker-compose.yml

The committed `docker-compose.yml` shrinks to:

```yaml
services:
  node:
    build: { context: ., dockerfile: Dockerfile.node }
    ports: ["443:443", "8443:8443", "9090:9090"]
    environment:
      RUST_LOG: info
      TOWONEL_HUB_PUBLIC_URL: https://hub.example.com
      # TOWONEL_INVITE_HASH_KEY: ${TOWONEL_INVITE_HASH_KEY}   # or auto-gen
      # TOWONEL_EDGE_TLS_ACME_EMAIL: you@example.com           # for Let's Encrypt
    volumes: ["node-data:/data"]
    # ...healthcheck unchanged
```

(The committed file's `RUST_LOG`, ports, healthcheck and volume name stay.)

## Backward compatibility

1. **`TOWONEL_DATA_DIR` unset → zero behavior change.** Every existing
   deployment that pins its paths sees identical resolution.
2. **Explicit env vars always win** over `DATA_DIR`-derived defaults.
   Setting `TOWONEL_DATA_DIR=/data` and `TOWONEL_HUB_DB_DSN=/var/lib/hub.db`
   yields `/var/lib/hub.db`.
3. **No env var renamed, removed, or repurposed.** The deprecated
   `TOWONEL_EDGE_HUB_URLS` alias and its warning at
   `crates/towonel-node/src/config.rs:328` remain.
4. **Auto-gen invite-hash key is opt-in.** It only fires when env var is
   unset AND path is set. Operators not using `DATA_DIR` see today's exact
   error message.
5. **`EDGE_PUBLIC_ADDRESSES` derivation is opt-in.** Only fires when the
   list is empty AND `HUB_PUBLIC_URL` is set.

## Testing strategy

In `crates/towonel-node/src/config.rs::tests`:

1. **No-DATA_DIR baseline:** existing tests stay green unchanged.
2. **DATA_DIR cascade:** with `TOWONEL_DATA_DIR=/tmp/x`, identity path,
   hub_db DSN, operator-key path, TLS cert dir, invite-hash-key path all
   resolve under `/tmp/x`.
3. **Explicit override wins:** DATA_DIR set + each individual env var set
   → individual values used.
4. **Public-addresses derivation:** unset list + `HUB_PUBLIC_URL=https://h.example.com`
   → derived to `["h.example.com:443"]`. Explicit list overrides.
5. **Public-addresses derivation skipped when HUB_PUBLIC_URL missing:**
   list stays empty (today's behavior).
6. **Postgres DSN not derived from DATA_DIR:** DATA_DIR set + driver=postgres
   + no DSN → existing "DSN required for postgres" error.

In `crates/towonel-node/src/hub/mod.rs` (or a new `tests` module):

7. **Invite-hash key auto-gen:** non-existent path → file created, content
   parses as a valid `InviteHashKey`, file mode is 0o600.
8. **Invite-hash key reuse:** existing path with valid key → loaded
   without rewriting.
9. **Invite-hash env wins over file:** both set → env value used, file
   left alone.
10. **Invite-hash neither set:** today's error message preserved.

## Files touched

- `crates/towonel-node/src/config.rs` — `RawEnv` gains `data_dir` and
  `invite_hash_key_path`; cascade logic in `from_raw`; new tests.
- `crates/towonel-node/src/hub/mod.rs` — `load_invite_hash_key` becomes
  `load_or_generate_invite_hash_key(env_value, path_opt)`; new tests.
- `Dockerfile.node` — add `ENV TOWONEL_DATA_DIR=/data`.
- `docker-compose.yml` — shrink to the minimal required vars (kept as
  a documentation/example surface).
- `README.md` — env-var table updated to reflect new defaults and
  document `TOWONEL_DATA_DIR`.

## Open questions

None at design time. Per-test failures during implementation may surface
edge cases (e.g. how `envy` deserializes an empty string for an
`Option<PathBuf>`) that the implementation will need to handle locally.
