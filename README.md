# towonel

Self-hosted tunnel for exposing HTTP(S) services behind NAT, CGNAT, or
dynamic IPs without opening inbound ports.

[![CI](https://git.erwanleboucher.dev/eleboucher/towonel/actions/workflows/ci.yml/badge.svg)](https://git.erwanleboucher.dev/eleboucher/towonel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 2024](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org/)

> Status: **alpha**. Functional and covered by integration tests. Wire
> format and APIs may change between `0.0.x` releases.

## Features

- **TLS passthrough by default** — the edge forwards raw TLS; keys and
  request content stay on the origin.
- **Edge TLS termination** — optional per hostname, with on-demand
  Let's Encrypt issuance.
- **Stateless agent** — no disk state, no init. One invite token boots
  any number of replicas.
- **Post-quantum signed control plane** — all config entries signed
  with ML-DSA-65 (FIPS 204).
- **Pluggable storage** — SQLite for single-node, PostgreSQL for HA.
- **Prometheus metrics** for observability.

## Architecture

```
           Internet                        Your network
        (public VPS)                (homelab / k8s / VM)

 Client       towonel                    towonel-agent
   │        ┌─────────┐                      │
   │ TLS    │  hub    │◄── towonel <cmd>     │
   │ ────►  │  API    │                      │
   │        │         │   iroh QUIC stream   │
   │        │  edge   │◄────────────────────►│──► origin
   │        │  :443   │   (passthrough or    │
   │        │         │    terminate)        │
   │        └─────────┘                      │
```

An edge can also run in **edge-only** mode and subscribe to a remote
hub — useful for scaling the data plane horizontally across regions
while keeping a single control plane.

## Install

From source:

```bash
cargo build --release -p towonel-node -p towonel-agent
```

From the container registry:

```bash
docker pull git.erwanleboucher.dev/eleboucher/towonel-node:latest
docker pull git.erwanleboucher.dev/eleboucher/towonel-agent:latest
```

## Quick start

### 1. Run the hub on a public VPS

```bash
towonel
```

Keys in `node.key` and `operator.key` are generated on first boot.
Keep `operator.key` — it authenticates invite creation.

### 2. Create an invite

```bash
towonel invite create \
  --name alice \
  --hostnames 'app.alice.example.eu,*.alice.example.eu'
# tt_inv_2_<token>
```

On the hub host, `--hub-url` and `--api-key` default to the local
listen address and `operator.key`. Pass them explicitly when running
the CLI from another machine.

The token embeds the tenant signing seed, the hub URL, and the invite
secret. It is both the bootstrap credential and the runtime identity
for every agent in that tenant. Default expiry is `never`; pass
`--expires 48h` for a short-lived credential.

### 3. Run the agent

```bash
TOWONEL_INVITE_TOKEN=tt_inv_2_... \
TOWONEL_AGENT_SERVICES='[
  {"hostname":"app.alice.example.eu","origin":"127.0.0.1:8443"},
  {"hostname":"*.alice.example.eu","origin":"127.0.0.1:8080",
   "tls_mode":{"mode":"terminate"}}
]' towonel-agent
```

On boot the agent derives the tenant key from the token, generates a
fresh iroh identity, registers with the hub, and starts heartbeating.

### 4. Point DNS

```bash
dig +short app.alice.example.eu   # should resolve to the VPS IP
curl https://app.alice.example.eu
```

## Deployment

### Docker Compose

```bash
docker compose up -d
```

See [`docker-compose.yml`](docker-compose.yml) for the full stack and
environment surface.

### Kubernetes

The agent is stateless, so a plain `Deployment` scales horizontally.
Every replica shares the same invite token and generates its own
iroh identity; the hub drops dead replicas after `90s`.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: towonel-agent }
spec:
  replicas: 3
  selector: { matchLabels: { app: towonel-agent } }
  template:
    metadata: { labels: { app: towonel-agent } }
    spec:
      containers:
        - name: agent
          image: git.erwanleboucher.dev/eleboucher/towonel-agent:latest
          env:
            - name: TOWONEL_INVITE_TOKEN
              valueFrom:
                secretKeyRef: { name: towonel-bootstrap, key: token }
            - name: TOWONEL_AGENT_SERVICES
              valueFrom:
                configMapKeyRef: { name: towonel-agent-services, key: services.json }
```

No PVC, no `StatefulSet`, no init container.

## Configuration

All settings come from `TOWONEL_*` environment variables (flat names,
single underscore). Lists may be passed as CSV or JSON; structured
lists (tenants, services) require JSON.

### Hub

| Variable                            | Default        | Description                                               |
| ----------------------------------- | -------------- | --------------------------------------------------------- |
| `TOWONEL_IDENTITY_KEY_PATH`         | `node.key`     | Node identity key                                         |
| `TOWONEL_HUB_ENABLED`               | `true`         | Enable the hub API                                        |
| `TOWONEL_INVITE_HASH_KEY`           |                | Key for hashing invite secrets (must be set for security) |
| `TOWONEL_HUB_LISTEN_ADDR`           | `0.0.0.0:8443` | Hub API bind address                                      |
| `TOWONEL_HUB_PUBLIC_URL`            | derived        | URL embedded in invite tokens                             |
| `TOWONEL_HUB_OPERATOR_API_KEY_PATH` | `operator.key` | Operator API key file                                     |
| `TOWONEL_HUB_DB_DRIVER`             | `sqlite`       | `sqlite` or `postgres`                                    |
| `TOWONEL_HUB_DB_DSN`                | `hub.db`       | Connection string                                         |
| `TOWONEL_HUB_DB_MAX_OPEN_CONNS`     | `4` / `25`     | Pool size                                                 |

### Edge

| Variable                            | Default        | Description                    |
| ----------------------------------- | -------------- | ------------------------------ |
| `TOWONEL_EDGE_ENABLED`              | `true`         | Enable the edge listener       |
| `TOWONEL_EDGE_LISTEN_ADDR`          | `0.0.0.0:443`  | TLS bind address               |
| `TOWONEL_EDGE_HEALTH_LISTEN_ADDR`   | `0.0.0.0:9090` | Health + metrics               |
| `TOWONEL_EDGE_HUB_URL`              |                | Remote hub (edge-only mode); `TOWONEL_EDGE_HUB_URLS` accepted as deprecated alias |
| `TOWONEL_EDGE_PUBLIC_ADDRESSES`     |                | Addresses advertised to agents |
| `TOWONEL_EDGE_TLS_ACME_EMAIL`       |                | Enables Let's Encrypt issuance |
| `TOWONEL_EDGE_TLS_CERT_DIR`         | `/data/certs`  | Cert cache directory           |
| `TOWONEL_EDGE_TLS_ACME_STAGING`     | `false`        | Use Let's Encrypt staging      |
| `TOWONEL_EDGE_TLS_HTTP_LISTEN_ADDR` | `0.0.0.0:80`   | HTTP-01 responder              |

### Agent

| Variable                      | Description                                     |
| ----------------------------- | ----------------------------------------------- |
| `TOWONEL_INVITE_TOKEN`        | **Required.** `tt_inv_2_...` token from the hub |
| `TOWONEL_AGENT_SERVICES`      | JSON array of services                          |
| `TOWONEL_AGENT_TRUSTED_EDGES` | Optional override for trusted edge IDs          |

Service shape:

```json
{
  "hostname": "app.alice.example.eu",
  "origin": "127.0.0.1:8080",
  "origin_server_name": "optional SNI for the origin dial",
  "tls_mode": { "mode": "passthrough" }
}
```

### CLI

| Variable               | Description                               |
| ---------------------- | ----------------------------------------- |
| `TOWONEL_HUB_URL`      | Default `--hub-url`                       |
| `TOWONEL_OPERATOR_KEY` | Default `--api-key` for operator commands |

Full examples live in [`examples/agent.env.example`](examples/agent.env.example)
and [`examples/node.env.example`](examples/node.env.example).

## TLS modes

Mode is chosen per hostname by the agent via a signed
`SetHostnameTls` entry.

**Passthrough (default).** The edge reads SNI and forwards raw TLS to
the origin. The origin holds the cert. The edge sees neither keys
nor plaintext. ACME challenges work through the tunnel.

**Terminate.** The edge issues an on-demand Let's Encrypt cert for
the hostname and forwards plaintext to the agent.

- HTTP-01 issuance is triggered on first request, cached, renewed lazily.
- Requires inbound `:80` on the edge for challenges.
- Wildcards issue per exact subdomain. Subject to Let's Encrypt rate
  limits (50 certs/week/registered domain).
- Failures back off exponentially, then enter a 5-minute cooldown per
  hostname.

## Tenants and invites

Each invite is a tenant. Revoking an invite removes the tenant.

```bash
towonel invite create  --name bob --hostnames '*.bob.example.eu'
towonel invite list
towonel invite revoke  --id <invite-id>

towonel tenant remove  --tenant-id <hex>
towonel tenant leave   --key-path tenant.key --hub-url https://node.example.eu:8443
```

Tenants can manage their own hostnames without operator intervention:

```bash
towonel entry submit --op upsert-hostname --hostname new.alice.example.eu
towonel entry submit --op delete-hostname --hostname old.alice.example.eu
towonel entry list
```

## Edge nodes

Grow edge capacity by inviting additional VPS operators:

```bash
# on the hub -- non-expiring token by default, re-usable across restarts
towonel edge-invite create --name charlie-fra1

# on the new edge -- only this env var is required
TOWONEL_EDGE_INVITE_TOKEN=tt_edge_2_... towonel
```

The v2 edge token embeds a 32-byte seed that deterministically derives
the edge's iroh identity. The hub pre-registers the resulting `node_id`
at invite creation, so the edge can start immediately with no redemption
step and no persistent key file. Revoke via `towonel edge-invite revoke
--id <invite-id>`; the edge loses access on the next subscription
attempt.

## Security

- The edge sees SNI, source IPs, and byte counts — never bodies,
  headers, or TLS keys. A malicious edge can deny service but cannot
  read or forge traffic.
- All config entries are signed with ML-DSA-65 (FIPS 204, PQ).
- Invite tokens are bearer credentials: they carry the tenant signing
  seed. Treat them as secret. In-memory copies are zeroed on drop;
  `Debug` redacts the seed.
- Invite secrets are stored as BLAKE3 keyed hashes (keyed by a per-hub
  operator secret) and compared in constant time. Revoked invites return
  the same `401` as a wrong secret.
- Heartbeat signatures are body-bound; a captured header cannot be
  replayed with a different body.
- Per-IP rate limiting on public endpoints.

## HTTP API

| Method   | Path                       | Auth          | Description                                |
| -------- | -------------------------- | ------------- | ------------------------------------------ |
| `POST`   | `/v1/entries`              | tenant sig    | Submit a signed config entry               |
| `GET`    | `/v1/tenants/{id}/entries` | none          | List entries for a tenant                  |
| `GET`    | `/v1/health`               | none          | Hub health                                 |
| `GET`    | `/v1/edges`                | none          | List edge nodes                            |
| `GET`    | `/v1/routes/subscribe`     | edge sig      | SSE route stream                           |
| `POST`   | `/v1/bootstrap`            | invite secret | Pod boot                                   |
| `POST`   | `/v1/agent/heartbeat`      | agent sig     | Liveness (90s TTL)                         |
| `POST`   | `/v1/invites`              | operator      | Create invite                              |
| `GET`    | `/v1/invites`              | operator      | List invites                               |
| `DELETE` | `/v1/invites/{id}`         | operator      | Revoke invite                              |
| `POST`   | `/v1/edge-invites`         | operator      | Create edge invite (pre-registers node_id) |
| `GET`    | `/v1/edge-invites`         | operator      | List edge invites                          |
| `DELETE` | `/v1/edge-invites/{id}`    | operator      | Revoke edge invite                         |
| `DELETE` | `/v1/tenants/{id}`         | operator      | Remove tenant                              |

## Roadmap

- `towonel-access` client for non-HTTPS protocols (SSH, Postgres, RDP)
  by wrapping raw TCP in TLS to the edge with `SNI=target-hostname`,
  similar to `cloudflared access`.

## Contributing

```bash
make check   # fmt + clippy + unit tests
make e2e     # full docker compose integration test
```

CI runs on Forgejo Actions (`.forgejo/workflows/`). Tagging `v*`
triggers a release.

## License

MIT — see [LICENSE](LICENSE).
