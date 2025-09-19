"""
Infrastructure Admin Configuration
"""
from django.contrib import admin
from .models import (
    InfrastructureComponent, HealthMetric, SystemAlert, BackupJob, 
    BackupExecution, PerformanceMetric, DisasterRecoveryPlan, 
    DisasterRecoveryTest, MaintenanceWindow
)

@admin.register(InfrastructureComponent)
class InfrastructureComponentAdmin(admin.ModelAdmin):
    list_display = ('name', 'component_type', 'status', 'is_critical', 'is_monitored', 'last_check')
    list_filter = ('component_type', 'status', 'is_critical', 'is_monitored')
    search_fields = ('name', 'hostname', 'ip_address')
    readonly_fields = ('created_at', 'updated_at', 'last_check')

@admin.register(HealthMetric)
class HealthMetricAdmin(admin.ModelAdmin):
    list_display = ('component', 'metric_name', 'value', 'unit', 'timestamp')
    list_filter = ('metric_type', 'timestamp')
    search_fields = ('component__name', 'metric_name')
    readonly_fields = ('timestamp',)

@admin.register(SystemAlert)
class SystemAlertAdmin(admin.ModelAdmin):
    list_display = ('title', 'component', 'severity', 'status', 'created_at')
    list_filter = ('alert_type', 'severity', 'status', 'created_at')
    search_fields = ('title', 'component__name')
    readonly_fields = ('created_at', 'updated_at')

@admin.register(BackupJob)
class BackupJobAdmin(admin.ModelAdmin):
    list_display = ('name', 'backup_type', 'frequency', 'is_enabled', 'last_run', 'created_by')
    list_filter = ('backup_type', 'frequency', 'is_enabled')
    search_fields = ('name', 'description')
    readonly_fields = ('created_at', 'updated_at', 'last_run', 'next_run')

@admin.register(BackupExecution)
class BackupExecutionAdmin(admin.ModelAdmin):
    list_display = ('backup_job', 'status', 'started_at', 'duration', 'backup_size')
    list_filter = ('status', 'started_at')
    search_fields = ('backup_job__name',)
    readonly_fields = ('started_at', 'completed_at', 'duration')

@admin.register(PerformanceMetric)
class PerformanceMetricAdmin(admin.ModelAdmin):
    list_display = ('metric_name', 'category', 'value', 'unit', 'component', 'timestamp')
    list_filter = ('category', 'timestamp')
    search_fields = ('metric_name', 'component__name')
    readonly_fields = ('timestamp',)

@admin.register(DisasterRecoveryPlan)
class DisasterRecoveryPlanAdmin(admin.ModelAdmin):
    list_display = ('name', 'plan_type', 'status', 'priority', 'rto', 'rpo', 'last_tested')
    list_filter = ('plan_type', 'status', 'priority')
    search_fields = ('name', 'description')
    readonly_fields = ('last_updated',)

@admin.register(DisasterRecoveryTest)
class DisasterRecoveryTestAdmin(admin.ModelAdmin):
    list_display = ('test_name', 'dr_plan', 'test_type', 'status', 'scheduled_date', 'test_lead')
    list_filter = ('test_type', 'status', 'scheduled_date')
    search_fields = ('test_name', 'dr_plan__name')
    readonly_fields = ('started_at', 'completed_at', 'duration')

@admin.register(MaintenanceWindow)
class MaintenanceWindowAdmin(admin.ModelAdmin):
    list_display = ('title', 'maintenance_type', 'status', 'scheduled_start', 'assigned_to')
    list_filter = ('maintenance_type', 'status', 'scheduled_start')
    search_fields = ('title', 'description')
    readonly_fields = ('actual_start', 'actual_end')