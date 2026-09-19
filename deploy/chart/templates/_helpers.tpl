{{/* The stable service identity (architecture.md naming): Deployment, Service,
ServiceAccount and Helm release share it. */}}
{{- define "anvilkit-agent-mcp.name" -}}
anvilkit-agent-mcp
{{- end -}}

{{- define "anvilkit-agent-mcp.fullname" -}}
{{- if eq .Release.Name (include "anvilkit-agent-mcp.name" .) -}}
{{- .Release.Name -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "anvilkit-agent-mcp.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "anvilkit-agent-mcp.labels" -}}
app.kubernetes.io/name: {{ include "anvilkit-agent-mcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/component: mcp
app.kubernetes.io/part-of: anvilkit
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "anvilkit-agent-mcp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "anvilkit-agent-mcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "anvilkit-agent-mcp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "anvilkit-agent-mcp.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "anvilkit-agent-mcp.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "anvilkit-agent-mcp.relayImage" -}}
{{- if .Values.relay.image.digest -}}
{{- printf "%s@%s" .Values.relay.image.repository .Values.relay.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.relay.image.repository (default .Chart.AppVersion .Values.relay.image.tag) -}}
{{- end -}}
{{- end -}}

{{/* Required environment values, checked once for every template. */}}
{{- define "anvilkit-agent-mcp.require" -}}
{{- if not .Values.database.secret.name }}
{{- fail "database.secret.name is required: an existing Secret holding the application-role URL, mounted as the file ANVILKIT_MCP_DATABASE_URL_FILE names" }}
{{- end }}
{{- if not .Values.nats.url }}
{{- fail "nats.url is required: the JetStream placement of the forwarder (ANVILKIT_MCP_NATS_URL)" }}
{{- end }}
{{- if and .Values.relay.enabled (or (not .Values.relay.database.secret.name) (not .Values.relay.queue.secret.name)) }}
{{- fail "relay.database.secret.name and relay.queue.secret.name are required while relay.enabled is true: the relay role's database URL and the queue Valkey URL" }}
{{- end }}
{{- end -}}
