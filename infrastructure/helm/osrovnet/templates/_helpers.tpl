{{/*
Expand the name of the chart.
*/}}
{{- define "osrovnet.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "osrovnet.fullname" -}}
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
{{- define "osrovnet.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "osrovnet.labels" -}}
helm.sh/chart: {{ include "osrovnet.chart" . }}
{{ include "osrovnet.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: osrovnet
{{- end }}

{{/*
Selector labels
*/}}
{{- define "osrovnet.selectorLabels" -}}
app.kubernetes.io/name: {{ include "osrovnet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "osrovnet.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "osrovnet.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Backend labels
*/}}
{{- define "osrovnet.backend.labels" -}}
{{ include "osrovnet.labels" . }}
app.kubernetes.io/component: backend
{{- end }}

{{/*
Backend selector labels
*/}}
{{- define "osrovnet.backend.selectorLabels" -}}
{{ include "osrovnet.selectorLabels" . }}
app.kubernetes.io/component: backend
{{- end }}

{{/*
Frontend labels
*/}}
{{- define "osrovnet.frontend.labels" -}}
{{ include "osrovnet.labels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{/*
Frontend selector labels
*/}}
{{- define "osrovnet.frontend.selectorLabels" -}}
{{ include "osrovnet.selectorLabels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{/*
Celery labels
*/}}
{{- define "osrovnet.celery.labels" -}}
{{ include "osrovnet.labels" . }}
app.kubernetes.io/component: celery
{{- end }}

{{/*
Celery selector labels
*/}}
{{- define "osrovnet.celery.selectorLabels" -}}
{{ include "osrovnet.selectorLabels" . }}
app.kubernetes.io/component: celery
{{- end }}

{{/*
Create image pull secrets
*/}}
{{- define "osrovnet.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.global.imagePullSecrets }}
  - name: {{ .name }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create backend image name
*/}}
{{- define "osrovnet.backend.image" -}}
{{- printf "%s/%s:%s" .Values.global.imageRegistry .Values.image.backend.repository .Values.image.backend.tag }}
{{- end }}

{{/*
Create frontend image name
*/}}
{{- define "osrovnet.frontend.image" -}}
{{- printf "%s/%s:%s" .Values.global.imageRegistry .Values.image.frontend.repository .Values.image.frontend.tag }}
{{- end }}