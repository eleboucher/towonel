{{- if .Values.monitoring.dashboards.enabled }}
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "bjw-s.common.lib.chart.names.fullname" . }}-dashboard
  namespace: {{ .Values.monitoring.dashboards.namespace | default .Release.Namespace }}
  {{- with .Values.monitoring.dashboards.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  labels:
    {{- include "bjw-s.common.lib.metadata.allLabels" . | nindent 4 }}
    {{- if not .Values.monitoring.dashboards.grafanaOperator.enabled }}
    grafana_dashboard: "1"
    {{- end }}
    {{- with .Values.monitoring.dashboards.labels }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
data:
  towonel-agent.json: |
{{ .Files.Get "dashboards/towonel-agent.json" | nindent 4 }}
{{- end }}
