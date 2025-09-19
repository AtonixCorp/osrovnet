"""
Infrastructure Resilience API Serializers
"""
from rest_framework import serializers
from .models import (
    InfrastructureComponent, HealthMetric, SystemAlert, BackupJob, 
    BackupExecution, PerformanceMetric, DisasterRecoveryPlan, 
    DisasterRecoveryTest, MaintenanceWindow
)

class InfrastructureComponentSerializer(serializers.ModelSerializer):
    """Serializer for infrastructure components"""
    
    class Meta:
        model = InfrastructureComponent
        fields = '__all__'
        read_only_fields = ('created_at', 'updated_at', 'last_check')

class HealthMetricSerializer(serializers.ModelSerializer):
    """Serializer for health metrics"""
    
    component_name = serializers.CharField(source='component.name', read_only=True)
    
    class Meta:
        model = HealthMetric
        fields = '__all__'
        read_only_fields = ('timestamp',)

class SystemAlertSerializer(serializers.ModelSerializer):
    """Serializer for system alerts"""
    
    component_name = serializers.CharField(source='component.name', read_only=True)
    acknowledged_by_username = serializers.CharField(source='acknowledged_by.username', read_only=True)
    resolved_by_username = serializers.CharField(source='resolved_by.username', read_only=True)
    
    class Meta:
        model = SystemAlert
        fields = '__all__'
        read_only_fields = ('created_at', 'updated_at')

class BackupJobSerializer(serializers.ModelSerializer):
    """Serializer for backup jobs"""
    
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    last_execution_status = serializers.SerializerMethodField()
    next_execution = serializers.SerializerMethodField()
    
    class Meta:
        model = BackupJob
        fields = '__all__'
        read_only_fields = ('created_at', 'updated_at', 'last_run', 'next_run')
    
    def get_last_execution_status(self, obj):
        """Get status of last execution"""
        last_execution = obj.executions.order_by('-started_at').first()
        return last_execution.status if last_execution else None
    
    def get_next_execution(self, obj):
        """Get next scheduled execution time"""
        return obj.next_run

class BackupExecutionSerializer(serializers.ModelSerializer):
    """Serializer for backup executions"""
    
    backup_job_name = serializers.CharField(source='backup_job.name', read_only=True)
    backup_size_mb = serializers.SerializerMethodField()
    duration_minutes = serializers.SerializerMethodField()
    
    class Meta:
        model = BackupExecution
        fields = '__all__'
        read_only_fields = ('started_at', 'completed_at', 'duration')
    
    def get_backup_size_mb(self, obj):
        """Get backup size in MB"""
        if obj.backup_size:
            return round(obj.backup_size / (1024 * 1024), 2)
        return None
    
    def get_duration_minutes(self, obj):
        """Get duration in minutes"""
        if obj.duration:
            return round(obj.duration.total_seconds() / 60, 2)
        return None

class PerformanceMetricSerializer(serializers.ModelSerializer):
    """Serializer for performance metrics"""
    
    component_name = serializers.CharField(source='component.name', read_only=True)
    
    class Meta:
        model = PerformanceMetric
        fields = '__all__'
        read_only_fields = ('timestamp',)

class DisasterRecoveryPlanSerializer(serializers.ModelSerializer):
    """Serializer for disaster recovery plans"""
    
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    approved_by_username = serializers.CharField(source='approved_by.username', read_only=True)
    rto_hours = serializers.SerializerMethodField()
    rpo_hours = serializers.SerializerMethodField()
    
    class Meta:
        model = DisasterRecoveryPlan
        fields = '__all__'
        read_only_fields = ('last_updated',)
    
    def get_rto_hours(self, obj):
        """Get RTO in hours"""
        return round(obj.rto / 60, 2) if obj.rto else None
    
    def get_rpo_hours(self, obj):
        """Get RPO in hours"""
        return round(obj.rpo / 60, 2) if obj.rpo else None

class DisasterRecoveryTestSerializer(serializers.ModelSerializer):
    """Serializer for disaster recovery tests"""
    
    dr_plan_name = serializers.CharField(source='dr_plan.name', read_only=True)
    test_lead_username = serializers.CharField(source='test_lead.username', read_only=True)
    participant_usernames = serializers.SerializerMethodField()
    duration_hours = serializers.SerializerMethodField()
    
    class Meta:
        model = DisasterRecoveryTest
        fields = '__all__'
        read_only_fields = ('started_at', 'completed_at', 'duration')
    
    def get_participant_usernames(self, obj):
        """Get participant usernames"""
        return [user.username for user in obj.participants.all()]
    
    def get_duration_hours(self, obj):
        """Get duration in hours"""
        if obj.duration:
            return round(obj.duration.total_seconds() / 3600, 2)
        return None

class MaintenanceWindowSerializer(serializers.ModelSerializer):
    """Serializer for maintenance windows"""
    
    assigned_to_username = serializers.CharField(source='assigned_to.username', read_only=True)
    approved_by_username = serializers.CharField(source='approved_by.username', read_only=True)
    component_names = serializers.SerializerMethodField()
    duration_hours = serializers.SerializerMethodField()
    
    class Meta:
        model = MaintenanceWindow
        fields = '__all__'
        read_only_fields = ('actual_start', 'actual_end')
    
    def get_component_names(self, obj):
        """Get component names"""
        return [component.name for component in obj.components.all()]
    
    def get_duration_hours(self, obj):
        """Get scheduled duration in hours"""
        if obj.scheduled_start and obj.scheduled_end:
            duration = obj.scheduled_end - obj.scheduled_start
            return round(duration.total_seconds() / 3600, 2)
        return None

class SystemOverviewSerializer(serializers.Serializer):
    """Serializer for system overview data"""
    
    total_components = serializers.IntegerField()
    healthy_components = serializers.IntegerField()
    warning_components = serializers.IntegerField()
    critical_components = serializers.IntegerField()
    down_components = serializers.IntegerField()
    health_percentage = serializers.FloatField()
    open_alerts = serializers.IntegerField()
    critical_alerts = serializers.IntegerField()
    last_updated = serializers.DateTimeField()

class ComponentMetricsSerializer(serializers.Serializer):
    """Serializer for component metrics data"""
    
    timestamp = serializers.DateTimeField()
    metric_type = serializers.CharField()
    metric_name = serializers.CharField()
    value = serializers.FloatField()
    unit = serializers.CharField()