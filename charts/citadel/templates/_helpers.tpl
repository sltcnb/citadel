{{/*
Expand the name of the chart.
*/}}
{{- define "citadel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncated at 63 chars (DNS naming spec) and trailing dashes trimmed.
*/}}
{{- define "citadel.fullname" -}}
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
Chart name and version label value.
*/}}
{{- define "citadel.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "citadel.labels" -}}
helm.sh/chart: {{ include "citadel.chart" . }}
{{ include "citadel.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels (release-scoped, component added by callers).
*/}}
{{- define "citadel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "citadel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Resolve a component image reference.
Usage: {{ include "citadel.image" (dict "ctx" . "component" .Values.api) }}
When `image.digest` is set (sha256:...) the image is pinned by digest for
supply-chain integrity/reproducibility, rendered as repo:tag@digest so the tag
stays human-readable while the digest is authoritative.
*/}}
{{- define "citadel.image" -}}
{{- $registry := .ctx.Values.global.image.registry -}}
{{- $repo := .component.image.repository -}}
{{- $tag := .component.image.tag | default .ctx.Values.global.image.tag -}}
{{- $digest := .component.image.digest | default .ctx.Values.global.image.digest -}}
{{- $name := $repo -}}
{{- if $registry -}}
{{- $name = printf "%s/%s" (trimSuffix "/" $registry) $repo -}}
{{- end -}}
{{- if $digest -}}
{{- printf "%s:%s@%s" $name $tag $digest -}}
{{- else -}}
{{- printf "%s:%s" $name $tag -}}
{{- end -}}
{{- end }}

{{/*
Resolve a component imagePullPolicy with fallback to the global default.
*/}}
{{- define "citadel.pullPolicy" -}}
{{- default .ctx.Values.global.image.pullPolicy .component.image.pullPolicy -}}
{{- end }}

{{/*
imagePullSecrets block.
*/}}
{{- define "citadel.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}
