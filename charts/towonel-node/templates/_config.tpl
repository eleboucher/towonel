{{- /*
Derive the friendly hub/edge config into common's native values, mutating
.Values before the common loader renders. An enabled edge switches the workload
to a hostNetwork DaemonSet, binds the public listeners, and drops
allowPrivilegeEscalation (NoNewPrivs would block the file-cap bind of 443/80).
*/ -}}
{{- define "towonel-node.config" -}}
{{- $v := .Values -}}
{{- $hub := $v.hub -}}
{{- $edge := $v.edge -}}
{{- if not (or $hub.enabled $edge.enabled) }}
  {{- fail "at least one of hub.enabled or edge.enabled must be true" }}
{{- end -}}
{{- $container := $v.controllers.main.containers.main -}}

{{- /* Workload kind + strategy. */ -}}
{{- $kind := $v.workload.kind | default ($edge.enabled | ternary "daemonset" "deployment") -}}
{{- $_ := set $v.controllers.main "type" $kind -}}
{{- if eq $kind "deployment" -}}
  {{- $_ := set $v.controllers.main "strategy" ($v.workload.strategy | default "Recreate") -}}
{{- else -}}
  {{- $_ := unset $v.controllers.main "strategy" -}}
{{- end -}}

{{- /* Role + listener env (merges with caller-supplied app env). */ -}}
{{- $env := default dict $container.env -}}
{{- $_ := set $env "TOWONEL_HUB_ENABLED" ($hub.enabled | toString) -}}
{{- $_ := set $env "TOWONEL_EDGE_ENABLED" ($edge.enabled | toString) -}}
{{- if $hub.enabled -}}
  {{- $_ := set $env "TOWONEL_HUB_LISTEN_ADDR" (printf "0.0.0.0:%v" $hub.apiPort) -}}
  {{- $_ := set $env "TOWONEL_HUB_LINK_LISTEN_ADDR" (printf "0.0.0.0:%v" $hub.linkPort) -}}
  {{- $_ := set $env "TOWONEL_HUB_HEALTH_LISTEN_ADDR" (printf "0.0.0.0:%v" $hub.metricsPort) -}}
{{- end -}}
{{- if $edge.enabled -}}
  {{- $_ := set $env "TOWONEL_EDGE_LISTEN_ADDR" (printf "%s:%v" $edge.bindAddress $edge.httpsPort) -}}
  {{- $_ := set $env "TOWONEL_EDGE_HTTP_LISTEN_ADDR" (printf "%s:%v" $edge.bindAddress $edge.httpPort) -}}
  {{- $_ := set $env "TOWONEL_EDGE_HEALTH_LISTEN_ADDR" (printf "%s:%v" $edge.healthBindAddress $edge.metricsPort) -}}
  {{- $_ := set $env "TOWONEL_DATA_DIR" $edge.dataDir -}}
{{- end -}}
{{- $_ := set $container "env" $env -}}

{{- /* Container ports. */ -}}
{{- $ports := list -}}
{{- if $hub.enabled -}}
  {{- $ports = append $ports (dict "name" "hub-api" "containerPort" ($hub.apiPort | int) "protocol" "TCP") -}}
  {{- $ports = append $ports (dict "name" "hub-link" "containerPort" ($hub.linkPort | int) "protocol" "TCP") -}}
  {{- $ports = append $ports (dict "name" "hub-metrics" "containerPort" ($hub.metricsPort | int) "protocol" "TCP") -}}
{{- end -}}
{{- if $edge.enabled -}}
  {{- $ports = append $ports (dict "name" "edge" "containerPort" ($edge.httpsPort | int) "protocol" "TCP") -}}
  {{- $ports = append $ports (dict "name" "edge-http" "containerPort" ($edge.httpPort | int) "protocol" "TCP") -}}
  {{- $ports = append $ports (dict "name" "edge-metrics" "containerPort" ($edge.metricsPort | int) "protocol" "TCP") -}}
{{- end -}}
{{- $_ := set $container "ports" $ports -}}

{{- /* Role-default probes (the edge health listener, or the hub API). */ -}}
{{- $probePort := $edge.enabled | ternary "edge-metrics" "hub-api" -}}
{{- $healthPath := $edge.enabled | ternary "/health" "/v1/health" -}}
{{- $readyPath := $edge.enabled | ternary "/health" "/v1/readyz" -}}
{{- $_ := set $container "probes" (dict
    "startup" (dict "enabled" true "type" "HTTP" "path" $healthPath "port" $probePort "spec" (dict "periodSeconds" 5 "failureThreshold" 60))
    "liveness" (dict "enabled" true "type" "HTTP" "path" $healthPath "port" $probePort "spec" (dict "periodSeconds" 30))
    "readiness" (dict "enabled" true "type" "HTTP" "path" $readyPath "port" $probePort "spec" (dict "periodSeconds" 10))) -}}

{{- /* Role-default resources (explicit container.resources wins). */ -}}
{{- if empty $container.resources -}}
  {{- if $edge.enabled -}}
    {{- $_ := set $container "resources" (dict "requests" (dict "cpu" "500m" "memory" "256Mi") "limits" (dict "memory" "2Gi")) -}}
  {{- else -}}
    {{- $_ := set $container "resources" (dict "requests" (dict "cpu" "100m" "memory" "256Mi") "limits" (dict "memory" "512Mi")) -}}
  {{- end -}}
{{- end -}}

{{- /* Edge: drop allowPrivilegeEscalation, hostNetwork, data volume. */ -}}
{{- if $edge.enabled -}}
  {{- if $container.securityContext -}}
    {{- $_ := unset $container.securityContext "allowPrivilegeEscalation" -}}
  {{- end -}}
  {{- $_ := set $v.defaultPodOptions "hostNetwork" true -}}
  {{- if not $v.defaultPodOptions.dnsPolicy -}}
    {{- $_ := set $v.defaultPodOptions "dnsPolicy" "ClusterFirstWithHostNet" -}}
  {{- end -}}
  {{- $persistence := default dict $v.persistence -}}
  {{- $_ := set $persistence "data" (dict "type" "emptyDir" "globalMounts" (list (dict "path" $edge.dataDir))) -}}
  {{- $_ := set $v "persistence" $persistence -}}
{{- end -}}

{{- /* Service ports. */ -}}
{{- $svcPorts := dict -}}
{{- if $hub.enabled -}}
  {{- $_ := set $svcPorts "hub-api" (dict "port" ($hub.apiPort | int) "protocol" "TCP" "targetPort" "hub-api") -}}
  {{- $_ := set $svcPorts "hub-link" (dict "port" ($hub.linkPort | int) "protocol" "TCP" "targetPort" "hub-link") -}}
  {{- $_ := set $svcPorts "hub-metrics" (dict "port" ($hub.metricsPort | int) "protocol" "TCP" "targetPort" "hub-metrics") -}}
{{- end -}}
{{- if $edge.enabled -}}
  {{- $_ := set $svcPorts "edge" (dict "port" ($edge.httpsPort | int) "protocol" "TCP" "targetPort" "edge") -}}
  {{- $_ := set $svcPorts "edge-http" (dict "port" ($edge.httpPort | int) "protocol" "TCP" "targetPort" "edge-http") -}}
  {{- $_ := set $svcPorts "edge-metrics" (dict "port" ($edge.metricsPort | int) "protocol" "TCP" "targetPort" "edge-metrics") -}}
{{- end -}}
{{- $_ := set $v.service.main "ports" $svcPorts -}}

{{- /* ServiceMonitor endpoints (per enabled role). */ -}}
{{- $eps := list -}}
{{- if $hub.enabled -}}
  {{- $eps = append $eps (dict "port" "hub-metrics" "interval" "30s" "scrapeTimeout" "10s" "path" "/metrics") -}}
{{- end -}}
{{- if $edge.enabled -}}
  {{- $eps = append $eps (dict "port" "edge-metrics" "interval" "30s" "scrapeTimeout" "10s" "path" "/metrics") -}}
{{- end -}}
{{- $_ := set $v.serviceMonitor.main "endpoints" $eps -}}
{{- end -}}
