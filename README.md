# towonel

Self-hosted tunnel for exposing HTTP(S) services behind NAT, CGNAT, or
dynamic IPs without opening inbound ports.

[![CI](https://git.erwanleboucher.dev/eleboucher/towonel/actions/workflows/ci.yml/badge.svg)](https://git.erwanleboucher.dev/eleboucher/towonel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 2024](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org/)

> Status: **alpha**. Functional and covered by integration tests. Wire
> format and APIs may change between `0.0.x` releases.

## Quick start

You need:

- A public VPS for the **hub** (ports `80`, `443`, `8443` open).
- A machine that can reach your service for the **agent** (homelab, k8s, VM).
- A DNS record pointing your hostname at the VPS.

### 1. Run the hub

On the VPS:

```bash
docker pull git.erwanleboucher.dev/eleboucher/towonel-node:latest
docker run -d --name towonel \
  -p 80:80 -p 443:443 -p 8443:8443 \
  -v towonel-data:/data \
  -e TOWONEL_HUB_PUBLIC_URL=https://hub.example.eu \
  -e TOWONEL_EDGE_TLS_ACME_EMAIL=ops@example.eu \
  git.erwanleboucher.dev/eleboucher/towonel-node:latest
```

The image pins `TOWONEL_DATA_DIR=/data`, so every path-shaped env var
(`TOWONEL_IDENTITY_KEY_PATH`, `TOWONEL_HUB_DB_DSN`,
`TOWONEL_HUB_OPERATOR_API_KEY_PATH`, `TOWONEL_EDGE_TLS_CERT_DIR`,
`TOWONEL_INVITE_HASH_KEY_PATH`) defaults to a path under `/data`. Override
any of them individually if you want files elsewhere.

`node.key`, `operator.key`, and `invite_hash.key` are generated on first
boot. Keep `operator.key` (admin auth) and `invite_hash.key` (invalidates
every outstanding invite if lost). For production, set
`TOWONEL_INVITE_HASH_KEY` from a secret manager instead of relying on the
on-disk file.

### 2. Create an invite

```bash
docker exec towonel towonel invite create \
  --name alice \
  --hostnames 'app.alice.example.eu,*.alice.example.eu'
# tt_inv_2_<token>
```

The token carries the tenant identity and is the only secret the agent
needs. Default expiry is `never`; pass `--expires 48h` for a short-lived
credential.

### 3. Run the agent

On the machine that can reach your service:

```bash
docker run -d --name towonel-agent \
  --network host \
  -e TOWONEL_INVITE_TOKEN=tt_inv_2_... \
  -e TOWONEL_AGENT_SERVICES='[
    {"hostname":"app.alice.example.eu","origin":"127.0.0.1:8443"}
  ]' \
  git.erwanleboucher.dev/eleboucher/towonel-agent:latest
```

### 4. Point DNS

```bash
dig +short app.alice.example.eu   # should resolve to the VPS IP
curl https://app.alice.example.eu
```

Add more services by extending `TOWONEL_AGENT_SERVICES`. Add replicas by
running the agent container N times. Add regions by inviting another VPS
as an edge node (see [Edge nodes](#edge-nodes)).

## TLS modes

Mode is chosen per hostname.

**Passthrough (default).** The edge reads SNI and forwards raw TLS to
the origin. The origin holds the cert. The edge sees neither keys nor
plaintext. ACME challenges work through the tunnel.

**Terminate.** The edge issues an on-demand Let's Encrypt cert for the
hostname and forwards plaintext to the agent.

- HTTP-01 issuance is triggered on first request, cached, renewed lazily.
- Requires inbound `:80` on the edge for challenges.
- Wildcards issue per exact subdomain. Subject to Let's Encrypt rate
  limits (50 certs/week/registered domain).
- Failures back off exponentially, then enter a 5-minute cooldown per
  hostname.

Pin a mode in the service entry:

```json
{
  "hostname": "app.alice.example.eu",
  "origin": "127.0.0.1:8080",
  "tls_mode": { "mode": "terminate" }
}
```

### Passthrough behind Envoy / Envoy Gateway

> **Heads up.** In passthrough mode the agent prepends a **PROXY protocol
> v2** header to every connection so the origin can recover the real
> client IP. Envoy will reject the connection (or treat the header bytes
> as request bytes) unless you tell it to accept PROXY protocol.

For **Envoy Gateway**, attach a `ClientTrafficPolicy` to the listener:

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: ClientTrafficPolicy
metadata:
  name: envoy
spec:
  proxyProtocol:
    optional: true
```

For raw Envoy, enable the `envoy.filters.listener.proxy_protocol` listener
filter on the inbound listener.

If you don't want PROXY protocol at all (e.g. the origin doesn't speak it
and you don't care about client IP), set it explicitly on the service:

```json
{ "hostname": "app.example.eu", "origin": "127.0.0.1:8443", "proxy_protocol": "none" }
```

## Raw TCP services

Forward arbitrary TCP ports — SSH, Prometheus remote-write, databases,
anything that isn't TLS-with-SNI — alongside the regular HTTPS routes.

The agent declares the listen port; the edge picks it up automatically.
The VPS admin doesn't add anything per service.

```bash
TOWONEL_AGENT_TCP_SERVICES='[
  {"name":"forgejo-ssh", "origin":"forgejo:22",            "listen_port":2222},
  {"name":"prom-write",  "origin":"victoriametrics:8428",  "listen_port":9090}
]'
```

Each agent boot reconciles the hub against the agent's env: added
entries are upserted, removed entries are deleted, and stale agent IDs
for the tenant are revoked. The env is the source of truth — run at
most one agent per tenant. `towonel admin tenant leave` fully
decommissions a tenant in one shot.

Each port is unique per tenant and across tenants: claiming a port
already bound to a different service — yours or somebody else's — is
rejected at submission time. Privileged ports (`< 1024`) are blocked by
default — set `TOWONEL_HUB_ALLOW_PRIVILEGED_PORTS=true` on the hub to
allow them.

## Raw UDP services

The same model works for UDP — DNS, WireGuard, QUIC-over-UDP origins,
game traffic. Datagrams are framed onto the agent↔edge QUIC tunnel
(length-prefixed, up to 64 KiB each) and dispatched to a per-client
session on the agent side. TCP and UDP live in independent port
namespaces, so `2222/tcp` and `2222/udp` can coexist.

```bash
TOWONEL_AGENT_UDP_SERVICES='[
  {"name":"dns",        "origin":"127.0.0.1:5353",   "listen_port":5353},
  {"name":"wireguard",  "origin":"10.0.0.1:51820",   "listen_port":51820}
]'
```

Bindings publish, retire, and respect the privileged-port gate exactly
like TCP services. Sessions are reaped after 60 s of inactivity on
either side.

## Managing tenants and invites

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

On the hub host, `--hub-url` and `--api-key` default to the local listen
address and `operator.key`. Pass them explicitly when running the CLI
from another machine.

## Edge nodes

Grow edge capacity by inviting additional VPS operators:

```bash
# on the hub -- non-expiring token by default, re-usable across restarts
towonel edge-invite create --name charlie-fra1

# on the new edge -- only this env var is required
TOWONEL_EDGE_INVITE_TOKEN=tt_edge_2_... towonel
```

The edge token deterministically derives the edge's iroh identity, so
the new edge starts immediately with no redemption step and no persistent
key file. Revoke via `towonel edge-invite revoke --id <invite-id>`.

## Deployment

### Docker Compose

```bash
docker compose up -d
```

See [`docker-compose.yml`](docker-compose.yml) for the full stack and
environment surface.

## Configuration reference

All settings come from `TOWONEL_*` environment variables (flat names,
single underscore). Lists may be passed as CSV or JSON; structured
lists (tenants, services) require JSON.

Full examples live in [`examples/agent.env.example`](examples/agent.env.example)
and [`examples/node.env.example`](examples/node.env.example).

### Base directory

`TOWONEL_DATA_DIR` (the published Docker image pins it to `/data`) supplies
defaults for every path-shaped env var below. Set it once and the node
finds its identity, database, operator key, certs, and invite-hash key
inside that directory. Individual overrides always win.

| Variable           | Default | Cascades into                                                                                                                              |
| ------------------ | ------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `TOWONEL_DATA_DIR` | unset   | `IDENTITY_KEY_PATH`, `HUB_DB_DSN` (sqlite only), `HUB_OPERATOR_API_KEY_PATH`, `EDGE_TLS_CERT_DIR`, `INVITE_HASH_KEY_PATH` (see below)       |

### Hub

| Variable                            | Default                            | Description                                                                                |
| ----------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------ |
| `TOWONEL_IDENTITY_KEY_PATH`         | `${DATA_DIR}/node.key` or `node.key` | Node identity key                                                                          |
| `TOWONEL_HUB_ENABLED`               | `true`                             | Enable the hub API                                                                         |
| `TOWONEL_INVITE_HASH_KEY`           |                                    | Hex key for hashing invite secrets (optional if `INVITE_HASH_KEY_PATH` or `DATA_DIR` set)  |
| `TOWONEL_INVITE_HASH_KEY_PATH`      | `${DATA_DIR}/invite_hash.key`      | Where the hub reads/generates the invite-hash key when the env var is unset                |
| `TOWONEL_HUB_LISTEN_ADDR`           | `0.0.0.0:8443`                     | Hub API bind address                                                                       |
| `TOWONEL_HUB_PUBLIC_URL`            | derived                            | URL embedded in invite tokens                                                              |
| `TOWONEL_HUB_OPERATOR_API_KEY_PATH` | `${DATA_DIR}/operator.key` or `operator.key` | Operator API key file                                                                |
| `TOWONEL_HUB_DB_DRIVER`             | `sqlite`                           | `sqlite` or `postgres`                                                                     |
| `TOWONEL_HUB_DB_DSN`                | `${DATA_DIR}/hub.db` or `hub.db` (sqlite); required for postgres | Connection string                                            |
| `TOWONEL_HUB_DB_MAX_OPEN_CONNS`     | `4` / `25`                         | Pool size                                                                                  |
| `TOWONEL_HUB_ALLOW_PRIVILEGED_PORTS`| `false`                            | Allow tenants to claim TCP/UDP ports below 1024                                            |

### Edge

| Variable                            | Default                                | Description                                                                                  |
| ----------------------------------- | -------------------------------------- | -------------------------------------------------------------------------------------------- |
| `TOWONEL_EDGE_ENABLED`              | `true`                                 | Enable the edge listener                                                                     |
| `TOWONEL_EDGE_LISTEN_ADDR`          | `0.0.0.0:443`                          | TLS bind address                                                                             |
| `TOWONEL_EDGE_HEALTH_LISTEN_ADDR`   | `0.0.0.0:9090`                         | Health + metrics                                                                             |
| `TOWONEL_EDGE_HUB_URL`              |                                        | Remote hub (edge-only mode); `TOWONEL_EDGE_HUB_URLS` accepted as deprecated alias            |
| `TOWONEL_EDGE_PUBLIC_ADDRESSES`     | `<HUB_PUBLIC_URL host>:443` when unset | Addresses advertised to agents                                                               |
| `TOWONEL_EDGE_TLS_ACME_EMAIL`       |                                        | Enables Let's Encrypt issuance                                                               |
| `TOWONEL_EDGE_TLS_CERT_DIR`         | `${DATA_DIR}/certs` or `/data/certs`   | Cert cache directory                                                                         |
| `TOWONEL_EDGE_TLS_ACME_STAGING`     | `false`                                | Use Let's Encrypt staging                                                                    |
| `TOWONEL_EDGE_TLS_HTTP_LISTEN_ADDR` | `0.0.0.0:80`                           | HTTP-01 responder                                                                            |

### Agent

| Variable                       | Description                                       |
| ------------------------------ | ------------------------------------------------- |
| `TOWONEL_INVITE_TOKEN`         | **Required.** `tt_inv_2_...` token from the hub   |
| `TOWONEL_AGENT_SERVICES`       | JSON array of HTTPS services                      |
| `TOWONEL_AGENT_TCP_SERVICES`   | JSON array of raw TCP services (see above)        |
| `TOWONEL_AGENT_UDP_SERVICES`   | JSON array of raw UDP services (see above)        |
| `TOWONEL_AGENT_TRUSTED_EDGES`  | Optional override for trusted edge IDs            |

Service shape:

```json
{
  "hostname": "app.alice.example.eu",
  "origin": "127.0.0.1:8080",
  "origin_server_name": "optional SNI for the origin dial",
  "tls_mode": { "mode": "passthrough" },
  "proxy_protocol": "v2"
}
```

`proxy_protocol` defaults to `v2` for passthrough services and `none`
for terminated services.

### CLI

| Variable               | Description                               |
| ---------------------- | ----------------------------------------- |
| `TOWONEL_HUB_URL`      | Default `--hub-url`                       |
| `TOWONEL_OPERATOR_KEY` | Default `--api-key` for operator commands |

## Install from source

```bash
cargo build --release -p towonel-node -p towonel-agent
```

## Contributing

```bash
make check   # fmt + clippy + unit tests
make e2e     # full docker compose integration test
```

CI runs on Forgejo Actions (`.forgejo/workflows/`). Tagging `v*`
triggers a release.

## License

MIT — see [LICENSE](LICENSE).
