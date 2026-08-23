# towonel-node

![Version: 0.0.0](https://img.shields.io/badge/Version-0.0.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.0.0](https://img.shields.io/badge/AppVersion-0.0.0-informational?style=flat-square)

A Helm chart for the towonel node - hub control plane and/or public edge for towonel tunnels

**Homepage:** <https://codeberg.org/towonel/towonel>

## Usage

One towonel-node process runs the hub control plane, the public edge, or
both (`hub.enabled` / `edge.enabled`, both on by default). The workload
kind, networking, listeners, probes and resource defaults follow the
enabled roles: hub-only renders a Deployment; an enabled edge renders a
hostNetwork DaemonSet binding `:443`/`:80` on each node.

```sh
# hub + edge in one process (default, single-node topology)
helm install towonel oci://codeberg.org/towonel/charts/towonel-node \
  --namespace towonel --create-namespace

# hub only (control plane without a public listener)
helm install towonel-hub oci://codeberg.org/towonel/charts/towonel-node \
  --namespace towonel --set edge.enabled=false

# edge only, e.g. one release per region
helm install towonel-edge-eu oci://codeberg.org/towonel/charts/towonel-node \
  --namespace towonel --set hub.enabled=false
```

Deployment-specific configuration (database DSN, public URLs, region) is
passed through `env`/`envFrom`.

An enabled edge mounts a `data` volume at `edge.dataDir`, an `emptyDir`
unless you set `persistence.data`. The node generates its identity key
there (plus the hub KEK and invite-hash key when the hub shares the pod),
so an `emptyDir` regenerates them on every restart. Back it with a claim,
or pass the keys in as env.

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| towonel |  |  |

## Source Code

* <https://codeberg.org/towonel/towonel>

## Requirements

Kubernetes: `>=1.31.0-0`

| Repository | Name | Version |
|------------|------|---------|
| https://bjw-s-labs.github.io/helm-charts | common | 5.1.0 |

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| controllers.main.annotations | object | `{}` |  |
| controllers.main.containers.main.envFrom | list | `[]` |  |
| controllers.main.containers.main.image.digest | string | `""` | Pin the image by digest (sha256:...); the release pipeline fills it. |
| controllers.main.containers.main.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| controllers.main.containers.main.image.repository | string | `"codeberg.org/towonel/towonel-node"` | Image repository. |
| controllers.main.containers.main.image.tag | string | `"{{ .Chart.AppVersion }}"` | Image tag; defaults to the chart appVersion. |
| controllers.main.containers.main.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"add":["NET_BIND_SERVICE"],"drop":["ALL"]},"readOnlyRootFilesystem":true}` | Container securityContext (read-only root filesystem, drops ALL capabilities, keeps NET_BIND_SERVICE for privileged listeners). allowPrivilegeEscalation is dropped automatically when the edge is enabled — NoNewPrivs would block the file-cap bind of 443/80. |
| controllers.main.replicas | int | `1` | Replicas (Deployment only; only one hub replica is the active leader). |
| defaultPodOptions | object | `{"automountServiceAccountToken":false,"enableServiceLinks":false,"securityContext":{"fsGroup":10001,"runAsGroup":10001,"runAsNonRoot":true,"runAsUser":10001,"seccompProfile":{"type":"RuntimeDefault"}},"terminationGracePeriodSeconds":30}` | Pod-wide defaults applied to every controller. hostNetwork + dnsPolicy are set automatically when the edge is enabled. |
| defaultPodOptions.automountServiceAccountToken | bool | `false` | The node does not talk to the cluster API. |
| defaultPodOptions.securityContext | object | `{"fsGroup":10001,"runAsGroup":10001,"runAsNonRoot":true,"runAsUser":10001,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod-level securityContext: non-root uid/gid 10001. The edge binds its privileged host ports (443/80) as this non-root user via the binary's file capabilities, so it never runs as root. |
| defaultPodOptions.terminationGracePeriodSeconds | int | `30` | Grace period for in-flight connections on shutdown. |
| edge.bindAddress | string | `"[::]"` | Bind address for the public TLS and plain-HTTP listeners. "[::]" is dual-stack. |
| edge.dataDir | string | `"/data"` | Data directory backed by an emptyDir volume (TOWONEL_DATA_DIR). |
| edge.enabled | bool | `true` | Run the public edge (TOWONEL_EDGE_ENABLED). Switches the workload to a hostNetwork DaemonSet; pin it to the right nodes with nodeSelector/affinity. |
| edge.healthBindAddress | string | `"0.0.0.0"` | Bind address for the edge health/metrics listener. |
| edge.httpPort | int | `80` | Plain HTTP port for ACME HTTP-01 and redirects. |
| edge.httpsPort | int | `443` | Public TLS port. |
| edge.metricsPort | int | `9090` | Port serving edge health and Prometheus metrics. |
| global.fullnameOverride | string | `""` | Override the full release name. |
| global.nameOverride | string | `""` | Override the chart name used in resource names. |
| hub.apiPort | int | `8443` | Port the user/operator HTTP API listens on. |
| hub.bindAddress | string | `"0.0.0.0"` | Bind address for the API and hub-link listeners. "[::]" is dual-stack. |
| hub.enabled | bool | `true` | Run the hub control plane (TOWONEL_HUB_ENABLED). |
| hub.healthBindAddress | string | `"0.0.0.0"` | Bind address for the hub health/metrics listener. |
| hub.linkPort | int | `51444` | Port edges dial for the hub link. |
| hub.metricsPort | int | `9091` | Port serving hub health and Prometheus metrics. |
| hub.rateLimitBurst | int | `30` | Per-IP burst allowance on the public API (TOWONEL_HUB_RATE_LIMIT_BURST). |
| hub.rateLimitPerSecond | int | `5` | Per-IP requests/sec on the public API (TOWONEL_HUB_RATE_LIMIT_PER_SEC). |
| monitoring.dashboards.annotations | object | `{}` | Annotations added to the dashboard ConfigMap. |
| monitoring.dashboards.enabled | bool | `false` | Render the Grafana dashboard ConfigMap (for grafana-operator or the kube-prometheus-stack sidecar). The dashboard covers hub and edge metrics. |
| monitoring.dashboards.grafanaOperator.allowCrossNamespaceImport | bool | `true` | If true allows for a Grafana in any namespace to access this GrafanaDashboard. |
| monitoring.dashboards.grafanaOperator.enabled | bool | `false` | Render a GrafanaDashboard CR (grafana-operator) instead of a sidecar ConfigMap. |
| monitoring.dashboards.grafanaOperator.folder | string | `""` | Folder to create the dashboard in. |
| monitoring.dashboards.grafanaOperator.matchLabels | object | `{}` | Selector labels for the Grafana instance. Must be set when enabled. |
| monitoring.dashboards.grafanaOperator.resyncPeriod | string | `"10m"` | Resync period for the Grafana operator to check for updates to the dashboard. |
| monitoring.dashboards.labels | object | `{}` | Labels added to the dashboard ConfigMap. |
| monitoring.dashboards.namespace | string | `""` | Namespace for the dashboard objects; defaults to the release namespace. |
| monitoring.prometheusRule.additionalRuleLabels | object | `{}` | Extra labels added to every alert rule (e.g. cluster). |
| monitoring.prometheusRule.annotations | object | `{}` | PrometheusRule annotations. |
| monitoring.prometheusRule.enabled | bool | `false` | Create a PrometheusRule with the hub alerting rules. |
| monitoring.prometheusRule.labels | object | `{}` | PrometheusRule labels. |
| service | object | `{"main":{"controller":"main","primary":true,"type":"ClusterIP"}}` | Service exposing the enabled listeners (ports derived from the roles). |
| serviceMonitor | object | `{"main":{"enabled":false}}` | Prometheus Operator ServiceMonitor. Disabled by default; set enabled:true (requires the ServiceMonitor CRD). Endpoints are derived from the enabled roles. |
| workload.kind | string | `""` | Workload kind: deployment or daemonset. Empty picks the role default (daemonset when the edge is enabled, deployment otherwise). |
| workload.strategy | string | `""` | Deployment update strategy (hub-only). Empty defaults to Recreate, because the hub is active/passive: a surged pod only passes /v1/readyz once it wins the Postgres advisory lock the old leader holds, so the old pod must terminate first. RollingUpdate (maxUnavailable:0) would deadlock the rollout. |

---

_This README is generated by [helm-docs](https://github.com/norwoodj/helm-docs) from `Chart.yaml` and `values.yaml`. Edit those (or `README.md.gotmpl`) and run `mise run helm-docs`._
