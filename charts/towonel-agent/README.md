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

Kubernetes: `>=1.31.0-0`

| Repository | Name | Version |
|------------|------|---------|
| https://bjw-s-labs.github.io/helm-charts | common | 5.1.0 |

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| agent.healthBindAddress | string | `"0.0.0.0"` | Bind address for the health/metrics listener. "[::]" is dual-stack. |
| agent.healthPort | int | `9090` | Port serving health and Prometheus metrics (TOWONEL_AGENT_HEALTH_LISTEN_ADDR). |
| agent.inviteTokenSecret.key | string | `"TOWONEL_INVITE_TOKEN"` | Key inside the Secret. |
| agent.inviteTokenSecret.name | string | `""` | Name of the Secret holding the invite token (TOWONEL_INVITE_TOKEN). Leave empty to skip the env var. |
| agent.logLevel | string | `"info"` | Log level (RUST_LOG). |
| agent.services | list | `[]` | HTTPS services exposed through the tunnel (TOWONEL_AGENT_SERVICES). |
| agent.tcpServices | list | `[]` | Raw TCP services exposed through the tunnel (TOWONEL_AGENT_TCP_SERVICES). |
| agent.udpServices | list | `[]` | UDP services exposed through the tunnel (TOWONEL_AGENT_UDP_SERVICES). |
| controllers.main.annotations | object | `{}` |  |
| controllers.main.containers.main.image.digest | string | `""` | Pin the image by digest (sha256:...); the release pipeline fills it. |
| controllers.main.containers.main.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| controllers.main.containers.main.image.repository | string | `"codeberg.org/towonel/towonel-agent"` | Image repository. |
| controllers.main.containers.main.image.tag | string | `"{{ .Chart.AppVersion }}"` | Image tag; defaults to the chart appVersion. |
| controllers.main.containers.main.probes.liveness.enabled | bool | `true` |  |
| controllers.main.containers.main.probes.liveness.path | string | `"/healthz"` |  |
| controllers.main.containers.main.probes.liveness.port | string | `"metrics"` |  |
| controllers.main.containers.main.probes.liveness.spec.failureThreshold | int | `3` |  |
| controllers.main.containers.main.probes.liveness.spec.initialDelaySeconds | int | `10` |  |
| controllers.main.containers.main.probes.liveness.spec.periodSeconds | int | `30` |  |
| controllers.main.containers.main.probes.liveness.spec.timeoutSeconds | int | `3` |  |
| controllers.main.containers.main.probes.liveness.type | string | `"HTTP"` |  |
| controllers.main.containers.main.probes.readiness.enabled | bool | `true` |  |
| controllers.main.containers.main.probes.readiness.path | string | `"/healthz"` |  |
| controllers.main.containers.main.probes.readiness.port | string | `"metrics"` |  |
| controllers.main.containers.main.probes.readiness.spec.failureThreshold | int | `3` |  |
| controllers.main.containers.main.probes.readiness.spec.initialDelaySeconds | int | `3` |  |
| controllers.main.containers.main.probes.readiness.spec.periodSeconds | int | `10` |  |
| controllers.main.containers.main.probes.readiness.spec.timeoutSeconds | int | `3` |  |
| controllers.main.containers.main.probes.readiness.type | string | `"HTTP"` |  |
| controllers.main.containers.main.probes.startup.enabled | bool | `true` |  |
| controllers.main.containers.main.probes.startup.path | string | `"/healthz"` |  |
| controllers.main.containers.main.probes.startup.port | string | `"metrics"` |  |
| controllers.main.containers.main.probes.startup.spec.failureThreshold | int | `30` |  |
| controllers.main.containers.main.probes.startup.spec.initialDelaySeconds | int | `2` |  |
| controllers.main.containers.main.probes.startup.spec.periodSeconds | int | `2` |  |
| controllers.main.containers.main.probes.startup.type | string | `"HTTP"` |  |
| controllers.main.containers.main.resources | object | `{"limits":{"memory":"256Mi"},"requests":{"cpu":"50m","memory":"128Mi"}}` | Pod resource requests/limits. |
| controllers.main.containers.main.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true}` | Container securityContext (no privilege escalation, read-only root filesystem, drops ALL capabilities). |
| controllers.main.replicas | int | `2` | Number of agent replicas (two give edge-session redundancy). |
| controllers.main.strategy | string | `"RollingUpdate"` | Rolling update keeps an agent serving during upgrades (stateless, 2 replicas). |
| controllers.main.type | string | `"deployment"` |  |
| defaultPodOptions | object | `{"automountServiceAccountToken":false,"enableServiceLinks":false,"securityContext":{"fsGroup":10001,"runAsGroup":10001,"runAsNonRoot":true,"runAsUser":10001,"seccompProfile":{"type":"RuntimeDefault"}},"terminationGracePeriodSeconds":30}` | Pod-wide defaults applied to every controller. |
| defaultPodOptions.automountServiceAccountToken | bool | `false` | The agent does not talk to the cluster API unless directConnect is enabled. |
| defaultPodOptions.securityContext | object | `{"fsGroup":10001,"runAsGroup":10001,"runAsNonRoot":true,"runAsUser":10001,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod-level securityContext (runs as non-root uid/gid 10001). |
| defaultPodOptions.terminationGracePeriodSeconds | int | `30` | Grace period for in-flight streams on shutdown. |
| directConnect.annotations | object | `{}` | Annotations for the direct (NodePort) Service. |
| directConnect.enabled | bool | `false` | Enable relay-less direct connectivity (NodePort + node autodiscovery). |
| directConnect.irohPort | int | `51820` | Fixed iroh UDP port the agent binds and the NodePort targets (TOWONEL_AGENT_IROH_PORT). |
| directConnect.nodePort | string | `nil` | Explicit nodePort for the iroh UDP port; null lets Kubernetes assign one. |
| disableUdpGso | bool | `false` | Disable UDP segmentation offload (TOWONEL_DISABLE_UDP_GSO) for pod datapaths that drop offloaded sends. |
| extraLocalAddrs | string | `""` | Reachable local addresses advertised to edges, comma-separated host:port (TOWONEL_AGENT_EXTRA_LOCAL_ADDRS). |
| global.fullnameOverride | string | `""` | Override the full release name. |
| global.nameOverride | string | `""` | Override the chart name used in resource names. |
| hostNetwork | bool | `false` | Run the agent on the host network (workaround for pod datapaths that break QUIC UDP sends). dnsPolicy switches to ClusterFirstWithHostNet. |
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
| relayUrl | string | `""` | Relay URL(s), comma-separated (TOWONEL_AGENT_RELAY_URL). Empty uses the hub-advertised relay. |
| service | object | `{"main":{"controller":"main","ports":{"metrics":{"port":9090,"protocol":"TCP","targetPort":"metrics"}},"primary":true}}` | ClusterIP Service exposing the metrics endpoint (port derived from agent.healthPort). |
| serviceMonitor | object | `{"main":{"enabled":false,"endpoints":[{"interval":"30s","path":"/metrics","port":"metrics","scrapeTimeout":"10s"}]}}` | Prometheus Operator ServiceMonitor. Disabled by default; set enabled:true (requires the ServiceMonitor CRD). |

---

_This README is generated by [helm-docs](https://github.com/norwoodj/helm-docs) from `Chart.yaml` and `values.yaml`. Edit those (or `README.md.gotmpl`) and run `mise run helm-docs`._
