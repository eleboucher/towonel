# turbo-tunnel

> **Status: Alpha** -- Functional and tested, but APIs and wire format may change between versions.

Exposes HTTP(S) services behind NAT, CGNAT, or dynamic IPs without opening inbound ports. The edge never holds TLS keys, never decrypts traffic, and never sees request content.

**How it compares:** Like Cloudflare Tunnel but self-hosted, decentralized, and post-quantum signed. No accounts, no SaaS — just cryptographic keypairs and a VPS you control.

```
                       Internet                        Your Network
                    (public VPS)                   (homelab / k8s / VM)

 Client               turbo-node                    turbo-agent
   |                  ┌──────────┐                       |
   | TLS ClientHello  │ hub  API │◄─── turbo-cli         |
   | ──────────────►  │ (SQLite) │     (invites,         |
   |  (SNI: app.eu)   │          │      entries)         |
   |                  │ edge     │                       |
   |                  │ :443     │   iroh QUIC stream    |
   |                  │  [SNI]───┼──────────────────►    |
   |                  │          │  (hostname header     |
   |                  └──────────┘   + raw TLS bytes)    |
   |                      |                         [local origin]
   |                      |                              |
   | ◄──────── bidirectional encrypted bytes ──────────► |
   |                      |                              |
   | TLS terminated here  | never decrypted              | TLS terminated here
   | (by origin cert)     | (passthrough only)           | (origin holds key)

 Federation (optional):

   turbo-node A ◄──── HTTPS push ────► turbo-node B
       │          (tenants, entries,        │
       │           removals)                │
       ▼                                    ▼
   edge A ◄── SSE route stream        edge B ◄── SSE route stream
```

## Install

### From source

```bash
cargo build --release -p turbo-agent -p turbo-node -p turbo-cli
```

### Docker

```bash
docker pull git.erwanleboucher.dev/eleboucher/turbo-node:latest
docker pull git.erwanleboucher.dev/eleboucher/turbo-agent:latest
```

Or build locally:

```bash
docker build -f Dockerfile.node  -t turbo-node:latest .
docker build -f Dockerfile.agent -t turbo-agent:latest .
```

## Quick start

### 1. Start the node (operator, on a VPS)

```bash
turbo-node -c node.toml
```

Minimal `node.toml`:

```toml
[identity]
key_path = "node.key"

[hub]
enabled = true

[edge]
enabled = true
```

Or skip the file entirely and use env vars:

```bash
TURBO_IDENTITY__KEY_PATH=node.key turbo-node -c /dev/null
```

On first run, `node.key` and `operator.key` are auto-generated. Save the operator key — you'll need it to create invites. To generate keys ahead of time, any tool that writes 32 random bytes works:

```bash
openssl rand 32 > node.key
chmod 600 node.key
```

### 2. Invite a tenant (operator)

```bash
turbo-cli invite create \
  --hub-url https://node.example.eu:8443 \
  --name alice \
  --hostnames "app.alice.example.eu,*.alice.example.eu" \
  --expires 48h
# Prints: tt_inv_1_<token>
```

Send the token to Alice through a trusted channel.

### 3. Join and start the agent (Alice, behind NAT)

```bash
turbo-agent init --invite tt_inv_1_...
```

This generates keypairs, registers with the hub, and writes `~/.turbo-tunnel/state.toml`. Then edit `~/.turbo-tunnel/agent.toml`:

```toml
[[services]]
hostname = "app.alice.example.eu"
origin = "127.0.0.1:8443"
```

```bash
turbo-agent
```

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

# Or with turbo-cli (also prints the derived public identity)
turbo-cli tenant init --key-path tenant.key   # prints tenant_id + PQ public key
turbo-cli agent init --key-path agent.key     # prints agent_id
```

The tenant seed derives an ML-DSA-65 (post-quantum) signing keypair; the agent seed derives an Ed25519 keypair for iroh transport.

### Key backup

```bash
turbo-cli tenant export-key
# Prints: turbo-key-v1:<encrypted-backup>  (AES-256-GCM + argon2id)

turbo-cli tenant import-key --backup 'turbo-key-v1:...' --key-path tenant.key
```

## Manage tenants

Tenants are managed through the CLI and the hub's database — no config file edits.

```bash
turbo-cli invite create --name bob --hostnames "*.bob.example.eu" --expires 48h
turbo-cli invite list
turbo-cli invite revoke --id <invite-id>

# Operator evicts a tenant
turbo-cli tenant remove --tenant-id <hex-tenant-id>

# Tenant leaves voluntarily
turbo-cli tenant leave
```

## Add an agent to an existing tenant

When a tenant runs services on multiple machines:

```bash
turbo-agent add-agent --tenant-key ~/.turbo-tunnel/tenant.key --hub https://hub.example.eu:8443
```

## Add edge nodes

Scale out edge capacity by inviting VPS operators:

```bash
# Operator
turbo-cli edge-invite create --name charlie-fra1

# Charlie, on his VPS
turbo-node init --edge-invite tt_edge_1_...
turbo-node --config /etc/turbo-tunnel/node.toml
```

The edge subscribes to the hub's route stream and receives updates as tenants come and go.

## Signed config entries

Tenants manage their own hostnames and agents without operator intervention:

```bash
turbo-cli entry submit --op upsert-hostname --hostname new.alice.example.eu
turbo-cli entry submit --op upsert-agent --agent-id <hex-agent-id>
turbo-cli entry submit --op delete-hostname --hostname old.alice.example.eu
turbo-cli entry submit --op revoke-agent --agent-id <hex-agent-id>
turbo-cli entry list
```

## TLS at the origin

turbo-tunnel is SNI passthrough — your origin terminates TLS, not the edge. Common setups:

- **Caddy** (simplest): `app.your.eu { reverse_proxy myapp:8080 }` — auto-renews via ACME
- **nginx**: standard TLS termination config
- **Kubernetes**: cert-manager + Ingress, agent points at the cluster-internal HTTPS port

ACME challenges (Let's Encrypt) resolve through the tunnel automatically.

## Deploy

### Docker Compose

```bash
docker compose up -d
```

All configuration is via env vars in `docker-compose.yml`. Keys auto-generate on first run.

### Configuration

All settings are configurable via `TURBO_*` env vars (double underscore separates sections). A TOML file is optional — you can run purely from env vars.

| Env var | Default | Description |
|---------|---------|-------------|
| `TURBO_IDENTITY__KEY_PATH` | `node.key` | Node identity key |
| `TURBO_HUB__ENABLED` | `true` | Enable the hub API |
| `TURBO_HUB__LISTEN_ADDR` | `0.0.0.0:8443` | Hub API bind address |
| `TURBO_HUB__DB_PATH` | `hub.db` | SQLite database path |
| `TURBO_HUB__PUBLIC_URL` | `https://<listen_addr>` | URL embedded in invite tokens |
| `TURBO_HUB__OPERATOR_API_KEY_PATH` | `operator.key` | Operator API key file |
| `TURBO_HUB__DNS_WEBHOOK_URL` | | POST hostname changes to this URL |
| `TURBO_EDGE__ENABLED` | `true` | Enable the edge listener |
| `TURBO_EDGE__LISTEN_ADDR` | `0.0.0.0:443` | Edge TCP bind address |
| `TURBO_EDGE__HEALTH_LISTEN_ADDR` | `0.0.0.0:9090` | Health + Prometheus metrics |
| `TURBO_EDGE__HUB_URL` | | Remote hub URL (edge-only mode) |

turbo-agent (`TURBO_AGENT_*`):

| Env var | Description |
|---------|-------------|
| `TURBO_AGENT_SERVICES` | JSON array: `[{"hostname":"app.example.eu","origin":"127.0.0.1:8080"}]` |
| `TURBO_AGENT_IDENTITY__KEY_PATH` | Agent key path |
| `TURBO_AGENT_TRUSTED_EDGES` | JSON array of hex endpoint IDs |

turbo-cli:

| Env var | Description |
|---------|-------------|
| `TURBO_HUB_URL` | Default `--hub-url` for all commands |
| `TURBO_OPERATOR_KEY` | Default `--api-key` for operator commands |
| `TURBO_STATE` | Override `state.toml` path (default: `~/.turbo-tunnel/state.toml`) |

### Federation

Replicate tenants and entries across hub instances:

```bash
TURBO_HUB__PEERS='[{"url":"https://hub-b.example.eu:8443"}]'
```

### DNS automation

The hub POSTs a diff to a webhook whenever the set of active hostnames changes:

```bash
TURBO_HUB__DNS_WEBHOOK_URL=https://dns-sidecar.internal/update
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
| `POST` | `/v1/entries` | tenant sig | Submit a signed config entry |
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

## Contributing

```bash
make check    # fmt + clippy + tests
make e2e      # full Docker Compose e2e test
```

CI runs on Forgejo Actions (`.forgejo/workflows/`). Tag `v*` to trigger a release.

## License

TBD
