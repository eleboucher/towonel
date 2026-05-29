# towonel

Self-hosted tunnel for exposing HTTP(S) services behind NAT, CGNAT, or
dynamic IPs without opening inbound ports.

[![CI](https://codeberg.org/towonel/towonel/actions/workflows/ci.yml/badge.svg)](https://codeberg.org/towonel/towonel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 2024](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org/)

> Status: **alpha**. Functional and covered by integration tests. Wire
> format and APIs may change between `0.0.x` releases.

## How it works

Two processes, one persistent QUIC tunnel between them:

- **Hub + edge** runs on a public VPS. Accepts TLS on `:443`, peeks the
  SNI, and forwards the connection over an open QUIC stream to the
  matching agent. Also serves the hub control plane on `:8443` where
  agents register their hostnames and TCP/UDP services.
- **Agent** runs wherever your origin is reachable (homelab, k8s, behind
  CGNAT). It dials the edge over QUIC, holds the connection open, and
  forwards traffic to the origin.

Identity is post-quantum (ML-DSA-65) at the tenant level, Ed25519 at the
iroh transport layer. Agents authenticate to the hub with an invite
token; clients authenticate to the edge with the regular TLS handshake.

## Quick start

You need:

- A public VPS for the **hub** with TCP `443`, TCP `8443`, and UDP
  `51820` (iroh QUIC) open to the internet.
- A machine that can reach your service for the **agent** (homelab,
  k8s, VM). No inbound ports required.
- A DNS record pointing your hostname at the VPS.

### 1. Run the hub

On the VPS:

```bash
docker pull codeberg.org/towonel/towonel-node:latest
docker run -d --name towonel \
  -p 443:443 -p 8443:8443 -p 51820:51820/udp \
  -v towonel-data:/data \
  -e TOWONEL_HUB_PUBLIC_URL=https://hub.example.eu \
  -e TOWONEL_EDGE_ADVERTISED_ADDRESSES=hub.example.eu:443 \
  -e TOWONEL_EDGE_TLS_ACME_EMAIL=ops@example.eu \
  codeberg.org/towonel/towonel-node:latest
```

The image pins `TOWONEL_DATA_DIR=/data`; every path-shaped env var defaults
to a subpath under it. `node.key`, `operator.key`, and `invite_hash.key`
are generated on first boot — back up `operator.key` (admin auth) and
`invite_hash.key` (losing it invalidates every outstanding invite). For
production, set `TOWONEL_INVITE_HASH_KEY` from a secret manager.

iroh QUIC binds to UDP `51820` by default; override with
`TOWONEL_EDGE_IROH_PORT` if you need a different port (remember to
update the `-p` mapping too).

#### Bundled-Caddy variant

`Dockerfile.hub-caddy` ships the same `towonel` binary alongside Caddy
(with the `caddy-l4` plugin). Caddy binds 80/443 and L4-forwards to
towonel on internal ports with PROXY v2 — operators get a single image
to deploy instead of overriding `EDGE_LISTEN_ADDR`,
`EDGE_PROXY_PROTOCOL`, etc. Both processes
run under tini; if either exits, the container exits and Docker's
restart policy brings the whole thing back.

```bash
docker run -d --name towonel \
  -p 80:80 -p 443:443 -p 8443:8443 -p 51820:51820/udp \
  -v towonel-data:/data \
  -e TOWONEL_HUB_PUBLIC_URL=https://hub.example.eu \
  -e TOWONEL_EDGE_ADVERTISED_ADDRESSES=hub.example.eu:443 \
  -e TOWONEL_EDGE_TLS_ACME_EMAIL=ops@example.eu \
  codeberg.org/towonel/towonel-hub-caddy:latest
```

Replace the baked Caddyfile by mounting one at `/etc/caddy/Caddyfile`.
The hub API stays at `:8443` direct (not behind Caddy in this image).
iroh QUIC stays on `:51820/udp` direct as well — Caddy does not proxy
UDP here.

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
  codeberg.org/towonel/towonel-agent:latest
```

### 4. Point DNS

```bash
dig +short app.alice.example.eu   # should resolve to the VPS IP
curl https://app.alice.example.eu
```

Add more services by extending `TOWONEL_AGENT_SERVICES`. Add replicas by
running the agent container N times; each registers as an independent
session and the edge load-balances across them. Add regions by inviting
another VPS as an edge node (see [Edge nodes](#edge-nodes)).

## TLS modes

Mode is chosen per hostname.

**Passthrough (default).** The edge reads SNI and forwards raw TLS to
the origin. The origin holds the cert. The edge sees neither keys nor
plaintext. ACME challenges work through the tunnel.

**Terminate.** The edge issues an on-demand Let's Encrypt cert for the
hostname and forwards plaintext to the agent.

- TLS-ALPN-01 validation on `:443` — no port 80 needed. Any L4 proxy
  fronting the edge must pass the `acme-tls/1` ALPN through; stripping
  it breaks validation.
- First-request issuance, cached, renewed at ~1/3 lifetime remaining.
- OCSP staples fetched and refreshed automatically.
- Wildcards issue per exact subdomain. LE rate limits apply
  (50 certs/week/registered domain).
- Cert management via [`certon`](https://crates.io/crates/certon).

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

## Hub↔edge control link

For multi-VPS deployments where the hub runs separately from the edges,
hubs accept an optional persistent TCP control link from each remote
edge. The link carries:

- The route table — hubs push `RouteSnapshot` whenever tenants or agents
  change, so edges converge without polling.
- Hub signing pubkeys — distributed on link establishment so the edge
  can locally verify `EdgeCred`s presented by agents (no per-connection
  hub round-trip).
- Session events — the edge reports `SessionAdded` / `SessionRemoved`
  to keep `agent_liveness` fresh from QUIC session presence.
- Iroh endpoint aggregation — every connected edge reports its public
  iroh endpoints over the link; `POST /v1/bootstrap` returns the union
  so agents reach every reachable edge.

Enable on both ends by setting matching PSKs (`openssl rand -hex 32`):

```bash
# on the hub VPS
docker run … \
  -e TOWONEL_HUB_LINK_LISTEN_ADDR=0.0.0.0:51444 \
  -e TOWONEL_HUB_LINK_PSK=$(cat hub.link.psk) \
  …

# on each edge VPS
docker run … \
  -e TOWONEL_EDGE_HUB_LINK_ADDR=hub.example.eu:51444 \
  -e TOWONEL_EDGE_HUB_LINK_PSK=$(cat hub.link.psk) \
  …
```

The link is plain TCP — colocate hub and edges on a private overlay
(WireGuard / Tailscale) or a VPC, or stand up `stunnel`/`spiped` in
front. The current build does not wrap the link in TLS itself.

When `TOWONEL_EDGE_HUB_LINK_*` are unset, edge-only nodes fall back to
the legacy SSE federation transport via `TOWONEL_EDGE_HUB_URL`. The SSE
path will be removed in a future release; new deployments should use
the control link.

## Multi-region

Run one global hub and one or more edges per region for lower client
latency. Front the edges with GeoDNS or anycast so a client's TLS
connection lands on a nearby edge (that steering is external to towonel).

Region is scoped on both sides:

- Each edge declares the region it serves with `TOWONEL_EDGE_REGION`
  (default `EU`), reported to the hub over the control link.
- Each invite declares the region its agents belong to:

  ```bash
  towonel invite create --name alice \
    --hostnames 'app.alice.example.eu' \
    --region EU --failover-regions CA
  ```

At `POST /v1/bootstrap` the hub hands an agent only the edges whose
region matches its invite's `--region` (plus any `--failover-regions`);
the agent then dials all of them. Because the tunnel is reverse-dialed
(the agent dials the edge, never the reverse), an edge can only serve an
agent that dialed it — so run an agent+origin in each region you serve.
If no edge matches the invite's region, the hub falls back to returning
every edge so the agent is never stranded.

Anything left unset resolves to `EU`, so existing single-region
deployments keep working unchanged.

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

Required variables are marked **Required** in the Description column.
Conditions are spelled out next to the marker.

### Base directory

`TOWONEL_DATA_DIR` (`/data` in the Docker image) supplies defaults for
every path-shaped env var below. Individual overrides win. At least one
of `TOWONEL_DATA_DIR`, `TOWONEL_IDENTITY_KEY`, `TOWONEL_IDENTITY_KEY_PATH`,
or `TOWONEL_EDGE_INVITE_TOKEN` must be set so the node can resolve an
identity at startup.

| Variable           | Default | Cascades into                                                                                                             |
| ------------------ | ------- | ------------------------------------------------------------------------------------------------------------------------- |
| `TOWONEL_DATA_DIR` | unset   | `IDENTITY_KEY_PATH`, `HUB_DB_DSN` (sqlite only), `HUB_OPERATOR_API_KEY_PATH`, `EDGE_TLS_CERT_DIR`, `INVITE_HASH_KEY_PATH` |

### Hub

| Variable                             | Default                                      | Description                                                                  |
| ------------------------------------ | -------------------------------------------- | ---------------------------------------------------------------------------- |
| `TOWONEL_IDENTITY_KEY`               | derived from `IDENTITY_KEY_PATH`             | 32-byte hex node key. When set, the file at `IDENTITY_KEY_PATH` is not read |
| `TOWONEL_IDENTITY_KEY_PATH`          | `${DATA_DIR}/node.key` or `node.key`         | Node identity key (generated on first boot)                                  |
| `TOWONEL_HUB_ENABLED`                | `true`                                       | Enable the hub API                                                           |
| `TOWONEL_INVITE_HASH_KEY`            | derived from `INVITE_HASH_KEY_PATH`          | Hex key for hashing invite secrets (file generated on first boot when unset) |
| `TOWONEL_INVITE_HASH_KEY_PATH`       | `${DATA_DIR}/invite_hash.key`                | Where the hub reads/generates the invite-hash key                            |
| `TOWONEL_HUB_LISTEN_ADDR`            | `0.0.0.0:8443`                               | Hub API bind address                                                         |
| `TOWONEL_HUB_PUBLIC_URL`             | derived                                      | URL embedded in invite tokens                                                |
| `TOWONEL_HUB_OPERATOR_API_KEY`       | derived from `OPERATOR_API_KEY_PATH`         | Operator API key (string). When set, the file at `OPERATOR_API_KEY_PATH` is not read |
| `TOWONEL_HUB_OPERATOR_API_KEY_PATH`  | `${DATA_DIR}/operator.key` or `operator.key` | Operator API key file (generated on first boot)                              |
| `TOWONEL_HUB_DB_DRIVER`              | `sqlite`                                     | `sqlite` or `postgres`                                                       |
| `TOWONEL_HUB_DB_DSN`                 | `${DATA_DIR}/hub.db` or `hub.db` (sqlite)    | Connection string. **Required** for `postgres`                               |
| `TOWONEL_HUB_DB_MAX_OPEN_CONNS`      | `4` / `25`                                   | Pool size                                                                    |
| `TOWONEL_HUB_ALLOW_PRIVILEGED_PORTS` | `false`                                      | Allow tenants to claim TCP/UDP ports below 1024                              |
| `TOWONEL_HUB_KEK`                    | derived from `HUB_KEK_PATH`                  | 32-byte hex KEK that seals hub signing-key seeds. Must match across all hubs in a cluster |
| `TOWONEL_HUB_KEK_PATH`               | `${DATA_DIR}/hub_kek.key`                    | Where the hub reads/generates the KEK                                        |
| `TOWONEL_HUB_LINK_LISTEN_ADDR`       |                                              | Bind address for the optional hub↔edge control link (see [Hub↔edge control link](#hubedge-control-link)) |
| `TOWONEL_HUB_LINK_PSK`               |                                              | 32-byte hex PSK authenticating remote edges. Must match `TOWONEL_EDGE_HUB_LINK_PSK` on every edge |

### Edge

| Variable                            | Default                                | Description                                                                                                                                                            |
| ----------------------------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TOWONEL_EDGE_ENABLED`              | `true`                                 | Enable the edge listener                                                                                                                                               |
| `TOWONEL_EDGE_LISTEN_ADDR`          | `0.0.0.0:443`                          | TLS bind address                                                                                                                                                       |
| `TOWONEL_EDGE_HEALTH_LISTEN_ADDR`   | `0.0.0.0:9090`                         | Health + metrics                                                                                                                                                       |
| `TOWONEL_EDGE_INVITE_TOKEN`         |                                        | `tt_edge_inv_…` token from the hub. **Required** in edge-only mode unless both `EDGE_HUB_URL` and an identity (`IDENTITY_KEY_PATH` or `DATA_DIR`'s `node.key`) are set |
| `TOWONEL_EDGE_HUB_URL`              | derived from invite token              | Remote hub URL (edge-only mode). **Required** when no invite token is provided. `TOWONEL_EDGE_HUB_URLS` accepted as deprecated alias                                   |
| `TOWONEL_EDGE_ADVERTISED_ADDRESSES` | `<HUB_PUBLIC_URL host>:443` when unset | `host:port` agents/clients reach (the reverse proxy when one fronts the edge). `TOWONEL_EDGE_PUBLIC_ADDRESSES` accepted as deprecated alias                            |
| `TOWONEL_EDGE_TLS_ACME_EMAIL`       |                                        | LE account contact (TLS-ALPN-01). **Required** when any `EDGE_TLS_*` var is set                                                                                        |
| `TOWONEL_EDGE_TLS_CERT_DIR`         | `${DATA_DIR}/certs` or `/data/certs`   | Cert/storage directory                                                                                                                                                 |
| `TOWONEL_EDGE_TLS_ACME_STAGING`     | `false`                                | Use Let's Encrypt staging                                                                                                                                              |
| `TOWONEL_EDGE_IROH_PORT`            | `51820`                                | UDP port for the iroh QUIC socket. Operators forward this port through the firewall. Binds both `0.0.0.0` and `[::]` — IPv6 stack required          |
| `TOWONEL_EDGE_HUB_LINK_ADDR`        |                                        | `host:port` of the hub's control-link listener. Enables the modern control plane in place of SSE federation (see [Hub↔edge control link](#hubedge-control-link)) |
| `TOWONEL_EDGE_HUB_LINK_PSK`         |                                        | 32-byte hex PSK shared with the hub                                                                                                                                  |
| `TOWONEL_EDGE_REGION`               | `EU`                                   | Region this edge serves. The hub hands an agent only the edges whose region matches its invite's region (plus failover regions). See [Multi-region](#multi-region) |

### Agent

| Variable                      | Description                                                                       |
| ----------------------------- | --------------------------------------------------------------------------------- |
| `TOWONEL_INVITE_TOKEN`        | `tt_inv_2_…` token from the hub. **Required.**                                    |
| `TOWONEL_AGENT_SERVICES`      | JSON array of HTTPS services                                                      |
| `TOWONEL_AGENT_TCP_SERVICES`  | JSON array of raw TCP services (see above)                                        |
| `TOWONEL_AGENT_UDP_SERVICES`  | JSON array of raw UDP services (see above)                                        |
| `TOWONEL_AGENT_TRUSTED_EDGES` | Optional override for trusted edge IDs                                            |

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
