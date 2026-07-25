{{- /*
Derive the friendly `agent` config (plus relayUrl / directConnect / hostNetwork)
into common's native values, mutating .Values before the common loader renders.
*/ -}}
{{- define "towonel-agent.config" -}}
{{- $v := .Values -}}
{{- $a := $v.agent -}}
{{- $container := $v.controllers.main.containers.main -}}

{{- /* Container env (common map form). */ -}}
{{- $env := default dict $container.env -}}
{{- $_ := set $env "NODE_NAME" (dict "valueFrom" (dict "fieldRef" (dict "fieldPath" "spec.nodeName"))) -}}
{{- $_ := set $env "POD_NAMESPACE" (dict "valueFrom" (dict "fieldRef" (dict "fieldPath" "metadata.namespace"))) -}}
{{- $_ := set $env "RUST_LOG" ($a.logLevel | toString) -}}
{{- $_ := set $env "TOWONEL_AGENT_HEALTH_LISTEN_ADDR" (printf "%s:%v" $a.healthBindAddress $a.healthPort) -}}
{{- with $a.services }}{{- $_ := set $env "TOWONEL_AGENT_SERVICES" (toJson .) -}}{{- end }}
{{- with $a.tcpServices }}{{- $_ := set $env "TOWONEL_AGENT_TCP_SERVICES" (toJson .) -}}{{- end }}
{{- with $a.udpServices }}{{- $_ := set $env "TOWONEL_AGENT_UDP_SERVICES" (toJson .) -}}{{- end }}
{{- if $a.inviteTokenSecret.name }}
  {{- $_ := set $env "TOWONEL_INVITE_TOKEN" (dict "valueFrom" (dict "secretKeyRef" (dict "name" $a.inviteTokenSecret.name "key" $a.inviteTokenSecret.key))) -}}
{{- end }}
{{- with $v.relayUrl }}{{- $_ := set $env "TOWONEL_AGENT_RELAY_URL" . -}}{{- end }}
{{- with $v.extraLocalAddrs }}{{- $_ := set $env "TOWONEL_AGENT_EXTRA_LOCAL_ADDRS" . -}}{{- end }}
{{- if $v.disableUdpGso }}{{- $_ := set $env "TOWONEL_DISABLE_UDP_GSO" "true" -}}{{- end }}

{{- /* Container ports + Service metrics port (derived from healthPort). */ -}}
{{- $ports := list (dict "name" "metrics" "containerPort" ($a.healthPort | int) "protocol" "TCP") -}}
{{- $_ := set (index $v.service.main.ports "metrics") "port" ($a.healthPort | int) -}}

{{- /* hostNetwork workaround. */ -}}
{{- if $v.hostNetwork -}}
  {{- $_ := set $v.defaultPodOptions "hostNetwork" true -}}
  {{- if not $v.defaultPodOptions.dnsPolicy -}}
    {{- $_ := set $v.defaultPodOptions "dnsPolicy" "ClusterFirstWithHostNet" -}}
  {{- end -}}
{{- end -}}

{{- /* Relay-less direct connectivity. */ -}}
{{- if $v.directConnect.enabled -}}
  {{- $_ := set $v.defaultPodOptions "automountServiceAccountToken" true -}}
  {{- $_ := set $env "TOWONEL_AGENT_K8S_AUTODISCOVER" "true" -}}
  {{- $_ := set $env "TOWONEL_AGENT_K8S_SERVICE" (printf "%s-direct" (include "bjw-s.common.lib.chart.names.fullname" .)) -}}
  {{- $_ := set $env "TOWONEL_AGENT_IROH_PORT" ($v.directConnect.irohPort | toString) -}}
  {{- $ports = append $ports (dict "name" "iroh" "containerPort" ($v.directConnect.irohPort | int) "protocol" "UDP") -}}
  {{- $irohPort := dict "port" ($v.directConnect.irohPort | int) "protocol" "UDP" "targetPort" "iroh" -}}
  {{- with $v.directConnect.nodePort }}{{- $_ := set $irohPort "nodePort" (. | int) -}}{{- end }}
  {{- $_ := set $v.service "direct" (dict "controller" "main" "type" "NodePort" "annotations" $v.directConnect.annotations "ports" (dict "iroh" $irohPort)) -}}
  {{- $_ := set $v "serviceAccount" (dict "main" dict) -}}
  {{- $_ := set $v.controllers.main "serviceAccount" (dict "identifier" "main") -}}
  {{- $_ := set $v "rbac" (dict
      "roles" (dict
        "node-reader" (dict "type" "ClusterRole" "rules" (list (dict "apiGroups" (list "") "resources" (list "nodes") "verbs" (list "get"))))
        "service-reader" (dict "type" "Role" "rules" (list (dict "apiGroups" (list "") "resources" (list "services") "verbs" (list "get")))))
      "bindings" (dict
        "node-reader" (dict "type" "ClusterRoleBinding" "roleRef" (dict "identifier" "node-reader") "subjects" (list (dict "identifier" "main")))
        "service-reader" (dict "type" "RoleBinding" "roleRef" (dict "identifier" "service-reader") "subjects" (list (dict "identifier" "main"))))) -}}
{{- end -}}

{{- $_ := set $container "env" $env -}}
{{- $_ := set $container "ports" $ports -}}
{{- end -}}
