from rest_framework import viewsets, mixins
from rest_framework.decorators import action
from rest_framework.response import Response
from django.utils import timezone
import json
from .models import Metric, Event, ReportDefinition, ScheduledReport
from .serializers import MetricSerializer, EventSerializer, ReportDefinitionSerializer, ScheduledReportSerializer


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
