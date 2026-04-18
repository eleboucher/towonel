# towonel

> **Status: Alpha** -- Functional and tested, but APIs and wire format may change between versions.

Exposes HTTP(S) services behind NAT, CGNAT, or dynamic IPs without opening inbound ports. Per hostname, the edge either passes raw TLS through to your origin (default — it never sees keys or request content) **or** terminates TLS with an on-demand Let's Encrypt cert. The agent picks.

**How it compares:** Like Cloudflare Tunnel but self-hosted, decentralized, and post-quantum signed. No accounts, no SaaS — just cryptographic keypairs and a VPS you control.

```
                       Internet                        Your Network
                    (public VPS)                   (homelab / k8s / VM)

 Client               towonel-node                    towonel-agent
   |                  ┌──────────┐                       |
   | TLS ClientHello  │ hub  API │◄─── towonel-cli         |
   | ──────────────►  │ (SQLite/ │     (invites)         |
   |  (SNI: app.eu)   │ Postgres)│                       |
   |  (SNI: app.eu)   │          │                       |
   |                  │ edge :443│◄─ SetHostnameTls ──── + (signed, on agent start)
   |                  │  (peek   │                       |
   |                  │   SNI)   │   iroh QUIC stream    |
   |                  │    │     │                       |
   |                  │    ▼     │                       |
   |                  │ Passthru?├──► raw TLS ──────────►|  [origin holds cert]
   |                  │    │     │                       |
   |                  │  Terminate                       |
   |                  │ (ACME)   ├──► plaintext ────────►|  [origin HTTP]
   |                  └──────────┘                       |

 Federation (optional):

   towonel-node A ◄──── HTTPS push ────► towonel-node B
       │          (tenants, entries,        │
       │           removals)                │
       ▼                                    ▼
   edge A ◄── SSE route stream        edge B ◄── SSE route stream
```

## Install

### From source

```bash
cargo build --release -p towonel-agent -p towonel-node -p towonel-cli
```

### Docker

```bash
docker pull git.erwanleboucher.dev/eleboucher/towonel-node:latest
docker pull git.erwanleboucher.dev/eleboucher/towonel-agent:latest
```

Or build locally:

```bash
docker build -f Dockerfile.node  -t towonel-node:latest .
docker build -f Dockerfile.agent -t towonel-agent:latest .
```

## Quick start

### 1. Start the node (operator, on a VPS)




```bash
  towonel-node
```

On first run, `node.key` and `operator.key` are auto-generated. Save the operator key — you'll need it to create invites. To generate keys ahead of time, any tool that writes 32 random bytes works:

```bash
openssl rand 32 > node.key
chmod 600 node.key
```

### 2. Invite a tenant (operator)

```bash
towonel-cli invite create \
  --hub-url https://node.example.eu:8443 \
  --name alice \
  --hostnames "app.alice.example.eu,*.alice.example.eu" \
  --expires 48h
# Prints: tt_inv_1_<token>
```

Send the token to Alice through a trusted channel.

### 3. Join and start the agent (Alice, behind NAT)

```bash
towonel-agent init --invite tt_inv_1_...
```


```bash
TOWONEL_AGENT_SERVICES='[
  {"hostname":"app.alice.example.eu","origin":"127.0.0.1:8443"},
  {"hostname":"*.alice.example.eu","origin":"127.0.0.1:8080",
   "tls_mode":{"mode":"terminate"}}
]' towonel-agent
```

- First service: passthrough (default). The origin terminates TLS.
- Second service: the edge terminates TLS using an on-demand Let's Encrypt cert, forwards plaintext to the origin. Useful when the origin can't hold a cert itself.

On startup the agent publishes each hostname's `tls_mode` to the hub as a signed `SetHostnameTls` entry. Edges pick it up via the existing route subscription.

### 4. Point DNS and test

Point `app.alice.example.eu` to the VPS IP, then:

```bash
curl https://app.alice.example.eu
```

## Keys

All keys auto-generate on first run. Every key is a 32-byte random seed file — you can create them with any tool:

```bash
# With openssl
openssl rand 32 > tenant.key && chmod 600 tenant.key
openssl rand 32 > agent.key  && chmod 600 agent.key

# Or with towonel-cli (also prints the derived public identity)
towonel-cli tenant init --key-path tenant.key   # prints tenant_id + PQ public key
towonel-cli agent init --key-path agent.key     # prints agent_id
```

The tenant seed derives an ML-DSA-65 (post-quantum) signing keypair; the agent seed derives an Ed25519 keypair for iroh transport.

### Key backup

```bash
towonel-cli tenant export-key
# Prints: towonel-key-v1:<encrypted-backup>  (AES-256-GCM + argon2id)

towonel-cli tenant import-key --backup 'towonel-key-v1:...' --key-path tenant.key
```

## Manage tenants

Tenants are managed through the CLI and the hub's database — no config file edits.

```bash
towonel-cli invite create --name bob --hostnames "*.bob.example.eu" --expires 48h
towonel-cli invite list
towonel-cli invite revoke --id <invite-id>

# Operator evicts a tenant
towonel-cli tenant remove --tenant-id <hex-tenant-id>

# Tenant leaves voluntarily
towonel-cli tenant leave
```

## Add an agent to an existing tenant

When a tenant runs services on multiple machines:

```bash
towonel-agent add-agent --tenant-key ~/.towonel/tenant.key --hub https://hub.example.eu:8443
```

## Add edge nodes

Scale out edge capacity by inviting VPS operators:

```bash
# Operator
towonel-cli edge-invite create --name charlie-fra1

# Charlie, on his VPS
towonel-node init --edge-invite tt_edge_1_...
towonel-node --config /etc/towonel/node.toml
```

The edge subscribes to the hub's route stream and receives updates as tenants come and go.

## Signed config entries

Tenants manage their own hostnames and agents without operator intervention:

```bash
towonel-cli entry submit --op upsert-hostname --hostname new.alice.example.eu
towonel-cli entry submit --op upsert-agent --agent-id <hex-agent-id>
towonel-cli entry submit --op delete-hostname --hostname old.alice.example.eu
towonel-cli entry submit --op revoke-agent --agent-id <hex-agent-id>
towonel-cli entry list
```

## TLS handling

Per-hostname, the agent picks one of two modes:

### Passthrough (default)

The edge extracts SNI and forwards raw TLS bytes to the origin. Your origin holds the cert and handles the handshake. The edge never sees keys or request content. ACME challenges (Let's Encrypt) resolve through the tunnel automatically.

Common origin setups:

- **nginx**: standard TLS termination config
- **Kubernetes**: cert-manager + Ingress, agent points at the cluster-internal HTTPS port

Alternatively, have the agent re-wrap the TCP connection with TLS before sending it to an HTTPS origin (like Cloudflare Tunnel's `originServerName`):

```json
{"hostname":"*.alice.example.eu","origin":"envoy.ns:443",
 "origin_server_name":"edge.alice.example.eu"}
```

### Edge termination

Set `tls_mode` on the service and the edge terminates TLS using an on-demand Let's Encrypt cert, then forwards plaintext to the agent which forwards to the origin over plain TCP.

```json
{"hostname":"*.bob.example.eu","origin":"127.0.0.1:8080",
 "tls_mode":{"mode":"terminate"}}
```

Cert lifecycle:

- First request for a hostname triggers HTTP-01 issuance against Let's Encrypt. Subsequent requests reuse the cached cert. Renewed lazily.
- Transient failures (network blips, ACME rate limits, challenge propagation) are retried with exponential backoff + jitter up to 3 attempts per request before the hostname enters a 5-minute failure cooldown.
- Requires `TOWONEL_EDGE__TLS__ACME_EMAIL` on the node and inbound :80 reachable for ACME challenges.
- Wildcards (`*.bob.example.eu`) issue per exact subdomain on first contact — no DNS-01 required. Subject to Let's Encrypt rate limits (50 certs/week/registered domain).
- The community member just needs a CNAME from their domain (e.g. `*.bob.example.eu`) to an edge hostname; no DNS provider API access needed.

## Deploy

### Docker Compose

```bash
docker compose up -d
```

All configuration is via env vars in `docker-compose.yml`. Keys auto-generate on first run.

### Configuration

All settings are configurable via `TOWONEL_*` env vars (double underscore separates sections). A TOML file is optional — you can run purely from env vars.

| Env var | Default | Description |
|---------|---------|-------------|
| `TOWONEL_IDENTITY__KEY_PATH` | `node.key` | Node identity key |
| `TOWONEL_HUB__ENABLED` | `true` | Enable the hub API |
| `TOWONEL_HUB__LISTEN_ADDR` | `0.0.0.0:8443` | Hub API bind address |
| `TOWONEL_HUB__DATABASE__DRIVER` | `sqlite` | `sqlite` or `postgres` |
| `TOWONEL_HUB__DATABASE__DSN` | `hub.db` (sqlite) | Connection string. Required for `postgres` (e.g. `postgres://user:pass@host/db`); for `sqlite` it's a file path or `sqlite://...` URL |
| `TOWONEL_HUB__DATABASE__MAX_OPEN_CONNS` | `4` sqlite / `25` postgres | Max open pool connections |
| `TOWONEL_HUB__DATABASE__MAX_IDLE_CONNS` | `4` sqlite / `10` postgres | Max idle pool connections |
| `TOWONEL_HUB__PUBLIC_URL` | `https://<listen_addr>` | URL embedded in invite tokens |
| `TOWONEL_HUB__OPERATOR_API_KEY_PATH` | `operator.key` | Operator API key file |
| `TOWONEL_HUB__DNS_WEBHOOK_URL` | | POST hostname changes to this URL |
| `TOWONEL_HUB__PEER_URLS` | | Federation peer URLs. CSV: `https://a,https://b` — or JSON |
| `TOWONEL_EDGE__ENABLED` | `true` | Enable the edge listener |
| `TOWONEL_EDGE__LISTEN_ADDR` | `0.0.0.0:443` | Edge TCP bind address (TLS passthrough + termination share this port) |
| `TOWONEL_EDGE__HEALTH_LISTEN_ADDR` | `0.0.0.0:9090` | Health + Prometheus metrics |
| `TOWONEL_EDGE__HUB_URLS` | | Remote hub URLs (edge-only mode). CSV or JSON list |
| `TOWONEL_EDGE__PUBLIC_ADDRESSES` | | Addresses this edge advertises to agents. CSV or JSON list |
| `TOWONEL_EDGE__TLS__ACME_EMAIL` | | Enables on-demand Let's Encrypt issuance |
| `TOWONEL_EDGE__TLS__CERT_DIR` | `/data/certs` | Where PEMs are cached |
| `TOWONEL_EDGE__TLS__ACME_STAGING` | `false` | Use LE staging (avoids rate limits while testing) |
| `TOWONEL_EDGE__TLS__HTTP_LISTEN_ADDR` | `0.0.0.0:80` | HTTP-01 challenge responder |

**Lists in env vars** — string-valued lists (`PEER_URLS`, `HUB_URLS`, `PUBLIC_ADDRESSES`) accept either comma-separated values (preferred in Kubernetes YAML) or a JSON array. Complex structured lists like `TOWONEL_TENANTS` require JSON.

towonel-agent (`TOWONEL_AGENT_*`):

| Env var | Description |
|---------|-------------|
| `TOWONEL_AGENT_SERVICES` | JSON array — see below |
| `TOWONEL_AGENT_IDENTITY__KEY_PATH` | Agent key path |
| `TOWONEL_AGENT_TRUSTED_EDGES` | JSON array of hex endpoint IDs |

`TOWONEL_AGENT_SERVICES` shape:

```json
[
  {
    "hostname": "app.alice.example.eu",
    "origin": "127.0.0.1:8080",
    "origin_server_name": "optional — TLS SNI to use when dialing the origin",
    "tls_mode": { "mode": "passthrough" }
  },
  {
    "hostname": "*.bob.example.eu",
    "origin": "127.0.0.1:9000",
    "tls_mode": { "mode": "terminate" }
  }
]
```

`tls_mode` is optional; missing means passthrough. On startup the agent POSTs a signed `SetHostnameTls` entry per service to the hub — edges pick it up via the existing route broadcast.

towonel-cli:

| Env var | Description |
|---------|-------------|
| `TOWONEL_HUB_URL` | Default `--hub-url` for all commands |
| `TOWONEL_OPERATOR_KEY` | Default `--api-key` for operator commands |
| `TOWONEL_STATE` | Override `state.toml` path (default: `~/.towonel/state.toml`) |

### Database

The hub stores invites, redeemed tenants, federated tenants, edge registrations, and signed config entries. Two drivers are supported:

- **SQLite** (default): zero-config single-node deployments. The DB file is created on first boot.
- **PostgreSQL**: recommended for multi-node operator setups or when you want external backups and HA on the storage layer.

TOML:

```toml
[hub.database]
driver = "postgres"
dsn = "postgres://towonel:secret@db.internal:5432/towonel_hub"
maxOpenConns = 25
maxIdleConns = 10
```

Or env vars:

```bash
TOWONEL_HUB__DATABASE__DRIVER=postgres
TOWONEL_HUB__DATABASE__DSN='postgres://towonel:secret@db.internal:5432/towonel_hub'
```

Migrations run automatically at boot via `sea-orm-migration`. The same schema applies to both drivers — no backend-specific branches.

### Federation

Replicate tenants and entries across hub instances. Peers are bidirectional over HTTPS. Each peer is pinned by its iroh `node_id` to close an MITM window at first contact — omit the id and the hub will still discover it via `GET /v1/health`, but will log a warn on startup.

```toml
[hub]
peers = [
  { url = "https://hub-b.example.eu:8443", node_id = "deadbeef..." },
  { url = "https://hub-c.example.eu:8443", node_id = "cafebabe..." },
]
```

Via env (JSON — structured config doesn't fit CSV):

```bash
TOWONEL_HUB__PEERS='[{"url":"https://hub-b.example.eu:8443","node_id":"deadbeef..."}]'
```

Get a peer's `node_id` from its `GET /v1/health` before pinning.

Push state (which tenants/entries have been delivered to which peer) is persisted, so a hub restart does not re-push everything. Inbound pushes are Ed25519-signed with replay protection.

### DNS automation

The hub POSTs a diff to a webhook whenever the set of active hostnames changes:

```bash
TOWONEL_HUB__DNS_WEBHOOK_URL=https://dns-sidecar.internal/update
```

Payload:

```json
{ "added": ["app.alice.example.eu"], "removed": ["old.example.eu"] }
```

Write a small HTTP handler that receives this and calls your DNS provider (Cloudflare, Route53, OVH, etc.) to create/remove A records pointing at the edge IP.

## Security

- The edge sees only SNI hostnames, source IPs, and byte counts — never request bodies, headers, or TLS keys
- A malicious edge operator can deny service but cannot read or forge traffic
- All config entries are signed with ML-DSA-65 (FIPS 204, post-quantum)
- Invite secrets are SHA-256 hashed at rest, compared in constant time
- Per-IP rate limiting on public endpoints
- Federation pushes are Ed25519-signed with replay protection

## API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/v1/entries` | tenant sig | Submit a signed config entry (`UpsertHostname`, `UpsertAgent`, `SetHostnameTls`, etc.) |
| `GET` | `/v1/tenants/{id}/entries` | none | List entries for a tenant |
| `GET` | `/v1/health` | none | Hub health check |
| `GET` | `/v1/edges` | none | List edge nodes |
| `GET` | `/v1/routes/subscribe` | edge sig | SSE route stream |
| `POST` | `/v1/invites` | operator | Create invite |
| `GET` | `/v1/invites` | operator | List invites |
| `DELETE` | `/v1/invites/{id}` | operator | Revoke invite |
| `POST` | `/v1/invites/redeem` | none | Redeem invite |
| `POST` | `/v1/edge-invites` | operator | Create edge invite |
| `GET` | `/v1/edge-invites` | operator | List edge invites |
| `DELETE` | `/v1/edge-invites/{id}` | operator | Revoke edge invite |
| `POST` | `/v1/edge-invites/redeem` | none | Redeem edge invite |
| `DELETE` | `/v1/tenants/{id}` | operator | Remove tenant |
| `GET` | `/v1/dns/records` | operator | Active hostnames + edge addresses |

## Roadmap

- [ ] **`towonel-access` client** for non-HTTPS protocols (SSH, Postgres, RDP).
  Wraps raw TCP in a TLS connection to the edge with `SNI=target-hostname`,
  the same way `cloudflared access` does. Lets multiple tenants share a
  single listener port (e.g. 2222) since routing stays SNI-based. Without
  this, SSH through the tunnel needs a per-tenant port exposed elsewhere.

## Contributing

```bash
make check    # fmt + clippy + tests
make e2e      # full Docker Compose e2e test
```

CI runs on Forgejo Actions (`.forgejo/workflows/`). Tag `v*` to trigger a release.

## License

MIT. See [LICENSE](LICENSE).
