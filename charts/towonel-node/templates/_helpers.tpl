{{/*
Expand the name of the chart.
*/}}
{{- define "towonel-node.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "towonel-node.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "towonel-node.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "towonel-node.labels" -}}
helm.sh/chart: {{ include "towonel-node.chart" . }}
{{ include "towonel-node.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "towonel-node.selectorLabels" -}}
app.kubernetes.io/name: {{ include "towonel-node.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "towonel-node.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "towonel-node.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the image name
*/}}
{{- define "towonel-node.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end }}

{{/*
Workload kind: DaemonSet when the edge is enabled, Deployment otherwise.
Overridable via workload.kind.
*/}}
{{- define "towonel-node.kind" -}}
{{- .Values.workload.kind | default (.Values.edge.enabled | ternary "DaemonSet" "Deployment") -}}
{{- end }}

{{/*
Pod-level securityContext. An explicit value wins; otherwise both roles run
non-root as uid/gid 10001. The edge binds the privileged host ports (443/80)
as this non-root user via file capabilities (the image is built with
`setcap cap_net_bind_service` on the binary), so it does not run as root.
*/}}
{{- define "towonel-node.podSecurityContext" -}}
{{- if .Values.podSecurityContext -}}
{{- toYaml .Values.podSecurityContext -}}
{{- else -}}
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
fsGroup: 10001
seccompProfile:
  type: RuntimeDefault
{{- end -}}
{{- end }}

{{/*
Container securityContext. The edge binds 443/80 as the non-root user through
file capabilities; allowPrivilegeEscalation:false sets NoNewPrivs, which blocks
the file-cap elevation, so it is stripped when the edge is enabled. hub-only
binds unprivileged ports and keeps it.
*/}}
{{- define "towonel-node.containerSecurityContext" -}}
{{- $sc := deepCopy .Values.securityContext -}}
{{- if .Values.edge.enabled -}}
{{- $_ := unset $sc "allowPrivilegeEscalation" -}}
{{- end -}}
{{- toYaml $sc -}}
{{- end }}

{{/*
Resources. An explicit value wins; otherwise the role default applies
(the edge terminates public TLS and needs the larger memory headroom).
*/}}
{{- define "towonel-node.resources" -}}
{{- if .Values.resources -}}
{{- toYaml .Values.resources -}}
{{- else if .Values.edge.enabled -}}
requests:
  cpu: 500m
  memory: 256Mi
limits:
  memory: 2Gi
{{- else -}}
requests:
  cpu: 100m
  memory: 256Mi
limits:
  memory: 512Mi
{{- end -}}
{{- end }}

{{/*
Role-default probes: the edge health listener when the edge is enabled,
the hub API otherwise. Explicit probe values win.
*/}}
{{- define "towonel-node.startupProbe" -}}
{{- if .Values.startupProbe -}}
{{- toYaml .Values.startupProbe -}}
{{- else -}}
httpGet:
  path: {{ .Values.edge.enabled | ternary "/health" "/v1/health" }}
  port: {{ .Values.edge.enabled | ternary "edge-metrics" "hub-api" }}
periodSeconds: 5
failureThreshold: 60
{{- end -}}
{{- end }}

{{- define "towonel-node.livenessProbe" -}}
{{- if .Values.livenessProbe -}}
{{- toYaml .Values.livenessProbe -}}
{{- else -}}
httpGet:
  path: {{ .Values.edge.enabled | ternary "/health" "/v1/health" }}
  port: {{ .Values.edge.enabled | ternary "edge-metrics" "hub-api" }}
periodSeconds: 30
{{- end -}}
{{- end }}

{{- define "towonel-node.readinessProbe" -}}
{{- if .Values.readinessProbe -}}
{{- toYaml .Values.readinessProbe -}}
{{- else -}}
httpGet:
  path: {{ .Values.edge.enabled | ternary "/health" "/v1/readyz" }}
  port: {{ .Values.edge.enabled | ternary "edge-metrics" "hub-api" }}
periodSeconds: 10
{{- end -}}
{{- end }}
