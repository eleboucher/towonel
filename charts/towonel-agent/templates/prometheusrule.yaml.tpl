{{- if .Values.monitoring.prometheusRule.enabled }}
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: {{ include "bjw-s.common.lib.chart.names.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "bjw-s.common.lib.metadata.allLabels" . | nindent 4 }}
    {{- with .Values.monitoring.prometheusRule.labels }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  {{- with .Values.monitoring.prometheusRule.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  groups:
    - name: towonel-agent.rules
      rules:
        {{- $job := include "bjw-s.common.lib.chart.names.fullname" . }}
        - alert: TowonelAgentEdgeLinkDown
          expr: |-
            max by (pod) (towonel_agent_edge_session_state{job="{{ $job }}"}) == 0
          for: 5m
          annotations:
            summary: >-
              Towonel agent {{ `{{ $labels.pod }}` }} holds no live edge session — the
              pod is up but its tunnel to the edge is down, so every service it
              exposes is unreachable
          labels:
            severity: critical
            {{- with .Values.monitoring.prometheusRule.additionalRuleLabels }}
            {{- toYaml . | nindent 12 }}
            {{- end }}

        - alert: TowonelAgentStreamsNearCap
          expr: |-
            towonel_agent_streams_active{job="{{ $job }}"} > 200
          for: 15m
          annotations:
            summary: >-
              Towonel agent {{ `{{ $labels.pod }}` }} is holding {{ `{{ $value }}` }} active
              streams, near the 256 cap — the stream-driven path that OOMKilled
              it before; raise the limit or shed load
          labels:
            severity: warning
            {{- with .Values.monitoring.prometheusRule.additionalRuleLabels }}
            {{- toYaml . | nindent 12 }}
            {{- end }}

        - alert: TowonelAgentReconnectStorm
          expr: |-
            sum by (pod) (rate(towonel_agent_edge_session_reconnects_total{job="{{ $job }}"}[15m])) > 0.2
          for: 15m
          annotations:
            summary: >-
              Towonel agent {{ `{{ $labels.pod }}` }} is reconnecting to the edge
              {{ `{{ $value | humanize }}` }} times/s — the hub link is flapping
          labels:
            severity: warning
            {{- with .Values.monitoring.prometheusRule.additionalRuleLabels }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
{{- end }}
