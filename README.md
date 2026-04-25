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
  -v towonel-data:/var/lib/towonel \
  -e TOWONEL_IDENTITY_KEY_PATH=/var/lib/towonel/node.key \
  -e TOWONEL_HUB_OPERATOR_API_KEY_PATH=/var/lib/towonel/operator.key \
  -e TOWONEL_HUB_DB_DSN=/var/lib/towonel/hub.db \
  git.erwanleboucher.dev/eleboucher/towonel-node:latest
```

`node.key` and `operator.key` are generated on first boot. Keep
`operator.key` — it authenticates all admin commands.

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

| Variable                            | Default        | Description                                                                       |
| ----------------------------------- | -------------- | --------------------------------------------------------------------------------- |
| `TOWONEL_EDGE_ENABLED`              | `true`         | Enable the edge listener                                                          |
| `TOWONEL_EDGE_LISTEN_ADDR`          | `0.0.0.0:443`  | TLS bind address                                                                  |
| `TOWONEL_EDGE_HEALTH_LISTEN_ADDR`   | `0.0.0.0:9090` | Health + metrics                                                                  |
| `TOWONEL_EDGE_HUB_URL`              |                | Remote hub (edge-only mode); `TOWONEL_EDGE_HUB_URLS` accepted as deprecated alias |
| `TOWONEL_EDGE_PUBLIC_ADDRESSES`     |                | Addresses advertised to agents                                                    |
| `TOWONEL_EDGE_TLS_ACME_EMAIL`       |                | Enables Let's Encrypt issuance                                                    |
| `TOWONEL_EDGE_TLS_CERT_DIR`         | `/data/certs`  | Cert cache directory                                                              |
| `TOWONEL_EDGE_TLS_ACME_STAGING`     | `false`        | Use Let's Encrypt staging                                                         |
| `TOWONEL_EDGE_TLS_HTTP_LISTEN_ADDR` | `0.0.0.0:80`   | HTTP-01 responder                                                                 |

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
