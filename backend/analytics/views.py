from rest_framework import viewsets, mixins
from rest_framework.decorators import action
from rest_framework.response import Response
from django.utils import timezone
import json
from .models import Metric, Event, ReportDefinition, ScheduledReport
from .serializers import MetricSerializer, EventSerializer, ReportDefinitionSerializer, ScheduledReportSerializer
from django.http import StreamingHttpResponse
from django.db.models import Q
from network_security.models import NetworkScan, Vulnerability
from .audit import AuditLog
import csv
import io


class MetricViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = Metric.objects.all().order_by('-timestamp')
    serializer_class = MetricSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        name = self.request.query_params.get('name')
        since = self.request.query_params.get('since')
        if name:
            qs = qs.filter(name=name)
        if since:
            try:
                from dateutil.parser import parse as parse_dt
                dt = parse_dt(since)
                qs = qs.filter(timestamp__gte=dt)
            except Exception:
                pass
        return qs


class EventViewSet(mixins.ListModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    queryset = Event.objects.all()
    serializer_class = EventSerializer


class ReportDefinitionViewSet(viewsets.ModelViewSet):
    queryset = ReportDefinition.objects.all()
    serializer_class = ReportDefinitionSerializer

    @action(detail=True, methods=['get'])
    def export(self, request, pk=None):
        report = self.get_object()
        fmt = request.query_params.get('format', 'json')
        data = ReportDefinitionSerializer(report).data

        if fmt == 'csv':
            # simple CSV serialization
            import csv, io
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(['key', 'value'])
            for k, v in (data.get('definition') or {}).items():
                writer.writerow([k, json.dumps(v)])
            return Response(buf.getvalue(), content_type='text/csv')

        return Response(data)


class ScheduledReportViewSet(viewsets.ModelViewSet):
    queryset = ScheduledReport.objects.all()
    serializer_class = ScheduledReportSerializer

    @action(detail=True, methods=['post'])
    def run_now(self, request, pk=None):
        schedule = self.get_object()
        # placeholder: trigger report generation synchronously
        schedule.last_run = timezone.now()
        schedule.save()
        return Response({'status': 'scheduled run executed', 'last_run': schedule.last_run})


def _parse_date_param(val):
    if not val:
        return None
    try:
        from dateutil.parser import parse as parse_dt
        return parse_dt(val)
    except Exception:
        return None


def generate_report(request):
    """Generate an on-demand report aggregating events, metrics, scans, vulnerabilities, and audit logs.

    Query params:
      format: json|csv (default json)
      since: ISO datetime
      until: ISO datetime
      event_type: optional to filter events
    """
    fmt = request.GET.get('format', 'json')
    since = _parse_date_param(request.GET.get('since'))
    until = _parse_date_param(request.GET.get('until'))
    event_type = request.GET.get('event_type')

    # Events
    events_qs = Event.objects.all()
    if event_type:
        events_qs = events_qs.filter(event_type=event_type)
    if since:
        events_qs = events_qs.filter(timestamp__gte=since)
    if until:
        events_qs = events_qs.filter(timestamp__lte=until)
    events = EventSerializer(events_qs.order_by('-timestamp')[:1000], many=True).data

    # Metrics (sample recent points)
    metrics_qs = Metric.objects.all()
    if since:
        metrics_qs = metrics_qs.filter(timestamp__gte=since)
    if until:
        metrics_qs = metrics_qs.filter(timestamp__lte=until)
    metrics = MetricSerializer(metrics_qs.order_by('-timestamp')[:2000], many=True).data

    # Scans and vulnerabilities
    scans_qs = NetworkScan.objects.all()
    if since:
        scans_qs = scans_qs.filter(started_at__gte=since)
    if until:
        scans_qs = scans_qs.filter(started_at__lte=until)
    scans = []
    for s in scans_qs.select_related('target').prefetch_related('hosts__ports__vulnerabilities')[:500]:
        scans.append({
            'id': s.id,
            'status': s.status,
            'target': getattr(s.target, 'target', None),
            'hosts_discovered': getattr(s, 'hosts_discovered', None),
            'started_at': getattr(s, 'started_at', None),
            'completed_at': getattr(s, 'completed_at', None),
        })

    vulns_qs = Vulnerability.objects.all()
    if since:
        vulns_qs = vulns_qs.filter(created_at__gte=since)
    if until:
        vulns_qs = vulns_qs.filter(created_at__lte=until)
    vulns = []
    for v in vulns_qs.select_related('port__host')[:2000]:
        vulns.append({
            'id': v.id,
            'title': v.title,
            'severity': v.severity,
            'host_ip': getattr(v, 'host_ip', None) or (getattr(getattr(v, 'port', None), 'host', None) and getattr(getattr(v, 'port', None).host, 'ip_address', None)),
            'cve_id': getattr(v, 'cve_id', None),
            'created_at': getattr(v, 'created_at', None),
        })

    # Audit logs
    audit_qs = AuditLog.objects.all()
    if since:
        audit_qs = audit_qs.filter(timestamp__gte=since)
    if until:
        audit_qs = audit_qs.filter(timestamp__lte=until)
    audits = []
    for a in audit_qs.select_related('actor')[:2000]:
        audits.append({
            'actor': str(a.actor) if a.actor else None,
            'action': a.action,
            'object_type': a.object_type,
            'object_id': a.object_id,
            'timestamp': a.timestamp,
            'details': a.details,
        })

    report = {
        'heading': 'Reports & Analytics',
        'description': 'Generate detailed reports, export operational data, and schedule recurring analytics to support compliance, audits, and strategic decision-making.',
        'generated_at': timezone.now(),
        'events': events,
        'metrics': metrics,
        'scans': scans,
        'vulnerabilities': vulns,
        'audit_logs': audits,
    }

    if fmt == 'csv':
        # Stream a CSV with multiple sections separated by blank lines
        def stream():
            buf = io.StringIO()
            writer = csv.writer(buf)
            # Header
            writer.writerow(['Reports & Analytics'])
            writer.writerow([])
            # Events
            writer.writerow(['Events'])
            writer.writerow(['id', 'event_type', 'timestamp', 'severity', 'payload'])
            yield buf.getvalue()
            buf.truncate(0); buf.seek(0)
            for e in events:
                writer.writerow([e.get('id'), e.get('event_type'), e.get('timestamp'), e.get('severity'), json.dumps(e.get('payload'))])
                yield buf.getvalue()
                buf.truncate(0); buf.seek(0)

            yield '\n'
            # Scans
            writer.writerow(['Scans'])
            writer.writerow(['id', 'status', 'target', 'hosts_discovered', 'started_at', 'completed_at'])
            yield buf.getvalue()
            buf.truncate(0); buf.seek(0)
            for s in scans:
                writer.writerow([s.get('id'), s.get('status'), s.get('target'), s.get('hosts_discovered'), s.get('started_at'), s.get('completed_at')])
                yield buf.getvalue()
                buf.truncate(0); buf.seek(0)

            yield '\n'
            # Vulnerabilities
            writer.writerow(['Vulnerabilities'])
            writer.writerow(['id', 'title', 'severity', 'host_ip', 'cve_id', 'created_at'])
            yield buf.getvalue()
            buf.truncate(0); buf.seek(0)
            for v in vulns:
                writer.writerow([v.get('id'), v.get('title'), v.get('severity'), v.get('host_ip'), v.get('cve_id'), v.get('created_at')])
                yield buf.getvalue()
                buf.truncate(0); buf.seek(0)

            yield '\n'
            # Audit Logs
            writer.writerow(['Audit Logs'])
            writer.writerow(['actor', 'action', 'object_type', 'object_id', 'timestamp', 'details'])
            yield buf.getvalue()
            buf.truncate(0); buf.seek(0)
            for a in audits:
                writer.writerow([a.get('actor'), a.get('action'), a.get('object_type'), a.get('object_id'), a.get('timestamp'), json.dumps(a.get('details'))])
                yield buf.getvalue()
                buf.truncate(0); buf.seek(0)

        resp = StreamingHttpResponse(stream(), content_type='text/csv')
        resp['Content-Disposition'] = 'attachment; filename="osrovnet-report.csv"'
        return resp

    # default json
    return Response(report)
