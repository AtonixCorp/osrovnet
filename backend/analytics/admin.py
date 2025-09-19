from django.contrib import admin
from .models import Metric, Event, ReportDefinition, ScheduledReport
from .audit import AuditLog


@admin.register(Metric)
class MetricAdmin(admin.ModelAdmin):
    list_display = ('name', 'timestamp', 'value')
    list_filter = ('name',)


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ('event_type', 'timestamp', 'severity')
    list_filter = ('event_type', 'severity')


@admin.register(ReportDefinition)
class ReportDefinitionAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at', 'updated_at')
    search_fields = ('name',)


@admin.register(ScheduledReport)
class ScheduledReportAdmin(admin.ModelAdmin):
    list_display = ('report', 'cron', 'enabled', 'last_run')
    list_filter = ('enabled',)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('action', 'actor', 'object_type', 'object_id', 'timestamp')
    readonly_fields = ('action', 'actor', 'object_type', 'object_id', 'timestamp', 'details')
    search_fields = ('action', 'object_type', 'object_id')

