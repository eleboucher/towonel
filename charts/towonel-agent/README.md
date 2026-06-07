# towonel-agent

![Version: 0.0.0](https://img.shields.io/badge/Version-0.0.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.0.0](https://img.shields.io/badge/AppVersion-0.0.0-informational?style=flat-square)

A Helm chart for the towonel agent - origin-side connector for towonel tunnels

**Homepage:** <https://codeberg.org/towonel/towonel>

## Usage

The agent runs next to your origin (homelab, k8s, behind CGNAT), dials the
edge over QUIC and forwards tunnel traffic to the configured services.

```sh
helm install towonel-agent oci://codeberg.org/towonel/charts/towonel-agent \
  --namespace network --create-namespace \
  --set agent.inviteTokenSecret.name=towonel-agent-secret
```

The exposed services are structured values (`agent.services`,
`agent.tcpServices`, `agent.udpServices`); the chart renders them into the
JSON environment variables the agent expects.

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
| agent.healthPort | int | `9090` | Port serving health and Prometheus metrics (TOWONEL_AGENT_HEALTH_LISTEN_ADDR). |
| agent.inviteTokenSecret.key | string | `"TOWONEL_INVITE_TOKEN"` | Key inside the Secret. |
| agent.inviteTokenSecret.name | string | `""` | Name of the Secret holding the invite token (TOWONEL_INVITE_TOKEN). Leave empty to skip the env var. |
| agent.logLevel | string | `"info"` | Log level (RUST_LOG). |
| agent.services | list | `[]` | HTTPS services exposed through the tunnel (TOWONEL_AGENT_SERVICES). |
| agent.tcpServices | list | `[]` | Raw TCP services exposed through the tunnel (TOWONEL_AGENT_TCP_SERVICES). |
| agent.udpServices | list | `[]` | UDP services exposed through the tunnel (TOWONEL_AGENT_UDP_SERVICES). |
| deploymentAnnotations | object | `{}` | Annotations added to the Deployment (e.g. reloader.stakater.com/auto). |
| env | list | `[]` | Extra environment variables passed to the container (k8s EnvVar list). |
| envFrom | list | `[]` | Extra envFrom sources. |
| fullnameOverride | string | `""` | Override the full release name. |
| image.digest | string | `""` | Pin the image by digest (sha256:...); when set, overrides the tag. The release pipeline fills it with the published image's digest. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| image.repository | string | `"codeberg.org/towonel/towonel-agent"` | Image repository. |
| image.tag | string | `""` | Overrides the image tag; defaults to the chart appVersion. |
| imagePullSecrets | list | `[]` | Image pull secrets for private registries. |
| livenessProbe | object | `{"failureThreshold":3,"httpGet":{"path":"/healthz","port":"metrics"},"initialDelaySeconds":10,"periodSeconds":30,"timeoutSeconds":3}` | Liveness probe. |
| monitoring.dashboards.annotations | object | `{}` | Annotations added to the dashboard ConfigMap. |
| monitoring.dashboards.enabled | bool | `false` | Render the Grafana dashboard ConfigMap (for grafana-operator or the kube-prometheus-stack sidecar). |
| monitoring.dashboards.grafanaOperator.allowCrossNamespaceImport | bool | `true` | If true allows for a Grafana in any namespace to access this GrafanaDashboard. |
| monitoring.dashboards.grafanaOperator.enabled | bool | `false` | Render a GrafanaDashboard CR (grafana-operator) instead of a sidecar ConfigMap. |
| monitoring.dashboards.grafanaOperator.folder | string | `""` | Folder to create the dashboard in. |
| monitoring.dashboards.grafanaOperator.matchLabels | object | `{}` | Selector labels for the Grafana instance. Must be set when enabled. |
| monitoring.dashboards.grafanaOperator.resyncPeriod | string | `"10m"` | Resync period for the Grafana operator to check for updates to the dashboard. |
| monitoring.dashboards.labels | object | `{}` | Labels added to the dashboard ConfigMap. |
| monitoring.dashboards.namespace | string | `""` | Namespace for the dashboard objects; defaults to the release namespace. |
| monitoring.prometheusRule.additionalRuleLabels | object | `{}` | Extra labels added to every alert rule (e.g. cluster). |
| monitoring.prometheusRule.annotations | object | `{}` | PrometheusRule annotations. |
| monitoring.prometheusRule.enabled | bool | `false` | Create a PrometheusRule with the agent alerting rules. |
| monitoring.prometheusRule.labels | object | `{}` | PrometheusRule labels. |
| monitoring.serviceMonitor.annotations | object | `{}` | ServiceMonitor annotations. |
| monitoring.serviceMonitor.enabled | bool | `false` | Create a Prometheus Operator ServiceMonitor (requires its CRDs). |
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
| podSecurityContext | object | `{"fsGroup":10001,"runAsGroup":10001,"runAsNonRoot":true,"runAsUser":10001,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod-level securityContext (runs as non-root uid/gid 10001). |
| readinessProbe | object | `{"failureThreshold":3,"httpGet":{"path":"/healthz","port":"metrics"},"initialDelaySeconds":3,"periodSeconds":10,"timeoutSeconds":3}` | Readiness probe. |
| replicaCount | int | `2` | Number of agent replicas (two give edge-session redundancy). |
| resources | object | `{"limits":{"memory":"256Mi"},"requests":{"cpu":"50m","memory":"128Mi"}}` | Pod resource requests/limits. |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true}` | Container securityContext (no privilege escalation, read-only root filesystem, drops ALL capabilities). |
| service.annotations | object | `{}` | Annotations for the Service. |
| service.type | string | `"ClusterIP"` | Service type. |
| serviceAccount.annotations | object | `{}` | Annotations for the ServiceAccount. |
| serviceAccount.automount | bool | `false` | Automount the API token (off by default: the agent does not talk to the cluster API). |
| serviceAccount.create | bool | `true` | Create a ServiceAccount. |
| serviceAccount.name | string | `""` | ServiceAccount name; generated from the release name if empty. |
| startupProbe | object | `{"failureThreshold":30,"httpGet":{"path":"/healthz","port":"metrics"},"initialDelaySeconds":2,"periodSeconds":2}` | Startup probe (on the named metrics port). |
| terminationGracePeriodSeconds | int | `30` | Grace period for in-flight streams on shutdown. |
| tolerations | list | `[]` | Tolerations for pod scheduling. |
| volumeMounts | list | `[]` | Additional volume mounts on the container. |
| volumes | list | `[]` | Additional volumes on the Deployment. |

---

_This README is generated by [helm-docs](https://github.com/norwoodj/helm-docs) from `Chart.yaml` and `values.yaml`. Edit those (or `README.md.gotmpl`) and run `mise run helm-docs`._
