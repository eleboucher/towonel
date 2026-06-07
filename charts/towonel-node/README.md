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

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| towonel |  |  |

## Source Code

* <https://codeberg.org/towonel/towonel>

## Requirements

Kubernetes: `>=1.25.0-0`

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity rules for pod scheduling. |
| dnsPolicy | string | `""` | DNS policy. Empty picks the role default (ClusterFirstWithHostNet when the edge is enabled, ClusterFirst otherwise). |
| edge.bindAddress | string | `"[::]"` | Bind address for the public TLS and plain-HTTP listeners. "[::]" is dual-stack: serves both IPv4 + IPv6. |
| edge.dataDir | string | `"/data"` | Data directory backed by an emptyDir volume (TOWONEL_DATA_DIR). |
| edge.enabled | bool | `true` | Run the public edge (TOWONEL_EDGE_ENABLED). Switches the workload to a hostNetwork DaemonSet; pin it to the right nodes with nodeSelector/affinity. |
| edge.healthBindAddress | string | `"0.0.0.0"` | Bind address for the edge health/metrics listener. |
| edge.httpPort | int | `80` | Plain HTTP port for ACME HTTP-01 and redirects (TOWONEL_EDGE_HTTP_LISTEN_ADDR). |
| edge.httpsPort | int | `443` | Public TLS port (TOWONEL_EDGE_LISTEN_ADDR). |
| edge.metricsPort | int | `9090` | Port serving edge health and Prometheus metrics (TOWONEL_EDGE_HEALTH_LISTEN_ADDR). |
| env | list | `[]` | Extra environment variables passed to the container (k8s EnvVar list). Deployment-specific configuration (DB DSN, public URLs, region, OTEL) goes here. |
| envFrom | list | `[]` | Extra envFrom sources (e.g. secrets created by ExternalSecret). |
| fullnameOverride | string | `""` | Override the full release name. |
| hub.apiPort | int | `8443` | Port the user/operator HTTP API listens on (TOWONEL_HUB_LISTEN_ADDR). |
| hub.enabled | bool | `true` | Run the hub control plane (TOWONEL_HUB_ENABLED). |
| hub.linkPort | int | `51444` | Port edges dial for the hub link (TOWONEL_HUB_LINK_LISTEN_ADDR). |
| hub.metricsPort | int | `9091` | Port serving hub health and Prometheus metrics (TOWONEL_HUB_HEALTH_LISTEN_ADDR). |
| image.digest | string | `""` | Pin the image by digest (sha256:...); when set, overrides the tag. The release pipeline fills it with the published image's digest. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| image.repository | string | `"codeberg.org/towonel/towonel-node"` | Image repository. |
| image.tag | string | `""` | Overrides the image tag; defaults to the chart appVersion. |
| imagePullSecrets | list | `[]` | Image pull secrets for private registries. |
| livenessProbe | object | `{}` | Liveness probe. Empty picks the role default (see startupProbe). |
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
| monitoring.prometheusRule.enabled | bool | `false` | Create a PrometheusRule with the hub alerting rules (rendered only when the hub is enabled). |
| monitoring.prometheusRule.labels | object | `{}` | PrometheusRule labels. |
| monitoring.serviceMonitor.annotations | object | `{}` | ServiceMonitor annotations. |
| monitoring.serviceMonitor.enabled | bool | `false` | Create a Prometheus Operator ServiceMonitor with an endpoint per enabled role (requires its CRDs). |
| monitoring.serviceMonitor.interval | string | `"30s"` | Scrape interval. |
| monitoring.serviceMonitor.labels | object | `{}` | ServiceMonitor labels. |
| monitoring.serviceMonitor.metricRelabelings | list | `[]` | Prometheus metric relabelings. |
| monitoring.serviceMonitor.path | string | `"/metrics"` | Metrics path. |
| monitoring.serviceMonitor.relabelings | list | `[]` | Prometheus relabelings (applied before scraping). |
| monitoring.serviceMonitor.scrapeTimeout | string | `"10s"` | Scrape timeout. |
| nameOverride | string | `""` | Override the chart name used in resource names. |
| nodeSelector | object | `{}` | Node selector for pod scheduling. |
| podAnnotations | object | `{}` | Annotations added to the pod. |
| podLabels | object | `{}` | Labels added to the pod. |
| podSecurityContext | object | `{}` | Pod-level securityContext. Empty picks the role default: non-root uid/gid 10001 for hub-only; unset when the edge is enabled (it must run as root to bind the privileged host ports). |
| readinessProbe | object | `{}` | Readiness probe. Empty picks the role default (/health on edge-metrics when the edge is enabled, /v1/readyz on hub-api otherwise). |
| replicaCount | int | `1` | Number of replicas (Deployment only; only one hub replica is the active leader). |
| resources | object | `{}` | Pod resource requests/limits. Empty picks the role default: 500m/256Mi requests + 2Gi limit when the edge is enabled, 100m/256Mi requests + 512Mi limit otherwise. |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"add":["NET_BIND_SERVICE"],"drop":["ALL"]},"readOnlyRootFilesystem":true}` | Container securityContext (read-only root filesystem, drops ALL capabilities, keeps NET_BIND_SERVICE for the edge's privileged listeners). |
| service.annotations | object | `{}` | Annotations for the Service. |
| service.enabled | bool | `true` | Create a Service for the enabled listeners. |
| service.type | string | `"ClusterIP"` | Service type. |
| serviceAccount.annotations | object | `{}` | Annotations for the ServiceAccount. |
| serviceAccount.automount | bool | `false` | Automount the API token (off by default: the node does not talk to the cluster API). |
| serviceAccount.create | bool | `true` | Create a ServiceAccount. |
| serviceAccount.name | string | `""` | ServiceAccount name; generated from the release name if empty. |
| startupProbe | object | `{}` | Startup probe. Empty picks the role default (/health on the edge-metrics port when the edge is enabled, /v1/health on hub-api otherwise). |
| terminationGracePeriodSeconds | int | `30` | Grace period for in-flight connections on shutdown. |
| tolerations | list | `[]` | Tolerations for pod scheduling. |
| updateStrategy | object | `{}` | Update strategy (DaemonSet only). |
| volumeMounts | list | `[]` | Additional volume mounts on the container. |
| volumes | list | `[]` | Additional volumes on the workload (e.g. postgres client certificates). |
| workload.annotations | object | `{}` | Annotations added to the workload (e.g. reloader.stakater.com/auto). |
| workload.kind | string | `""` | Workload kind: Deployment or DaemonSet. Empty picks the role default (DaemonSet when the edge is enabled, Deployment otherwise). |

---

_This README is generated by [helm-docs](https://github.com/norwoodj/helm-docs) from `Chart.yaml` and `values.yaml`. Edit those (or `README.md.gotmpl`) and run `mise run helm-docs`._
