"""
Infrastructure Resilience Models for OSROVNet
"""
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import json

class InfrastructureComponent(models.Model):
    """Infrastructure components being monitored"""
    
    COMPONENT_TYPES = [
        ('server', 'Server'),
        ('database', 'Database'),
        ('web_server', 'Web Server'),
        ('load_balancer', 'Load Balancer'),
        ('cache', 'Cache Server'),
        ('queue', 'Message Queue'),
        ('storage', 'Storage System'),
        ('network', 'Network Device'),
        ('application', 'Application Service'),
        ('container', 'Container'),
        ('vm', 'Virtual Machine'),
    ]
    
    STATUS_CHOICES = [
        ('healthy', 'Healthy'),
        ('warning', 'Warning'),
        ('critical', 'Critical'),
        ('down', 'Down'),
        ('maintenance', 'Maintenance'),
    ]
    
    name = models.CharField(max_length=255)
    component_type = models.CharField(max_length=20, choices=COMPONENT_TYPES)
    hostname = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    port = models.IntegerField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='healthy')
    description = models.TextField(blank=True)
    is_critical = models.BooleanField(default=False)
    is_monitored = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_check = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'infrastructure_components'
        indexes = [
            models.Index(fields=['status', 'is_monitored']),
            models.Index(fields=['component_type', 'status']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.component_type})"

class HealthMetric(models.Model):
    """Health metrics for infrastructure components"""
    
    METRIC_TYPES = [
        ('cpu_usage', 'CPU Usage'),
        ('memory_usage', 'Memory Usage'),
        ('disk_usage', 'Disk Usage'),
        ('network_io', 'Network I/O'),
        ('response_time', 'Response Time'),
        ('throughput', 'Throughput'),
        ('error_rate', 'Error Rate'),
        ('uptime', 'Uptime'),
        ('temperature', 'Temperature'),
        ('power_usage', 'Power Usage'),
        ('custom', 'Custom Metric'),
    ]
    
    component = models.ForeignKey(InfrastructureComponent, on_delete=models.CASCADE, related_name='metrics')
    metric_type = models.CharField(max_length=20, choices=METRIC_TYPES)
    metric_name = models.CharField(max_length=100)
    value = models.FloatField()
    unit = models.CharField(max_length=20, blank=True)
    threshold_warning = models.FloatField(null=True, blank=True)
    threshold_critical = models.FloatField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'health_metrics'
        indexes = [
            models.Index(fields=['component', 'timestamp']),
            models.Index(fields=['metric_type', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.component.name}: {self.metric_name} = {self.value}"

class SystemAlert(models.Model):
    """System alerts for infrastructure issues"""
    
    ALERT_TYPES = [
        ('performance', 'Performance'),
        ('availability', 'Availability'),
        ('capacity', 'Capacity'),
        ('security', 'Security'),
        ('configuration', 'Configuration'),
        ('backup', 'Backup'),
        ('recovery', 'Recovery'),
    ]
    
    SEVERITY_LEVELS = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('acknowledged', 'Acknowledged'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('suppressed', 'Suppressed'),
    ]
    
    component = models.ForeignKey(InfrastructureComponent, on_delete=models.CASCADE, related_name='alerts')
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    title = models.CharField(max_length=255)
    message = models.TextField()
    metric = models.ForeignKey(HealthMetric, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    acknowledged_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='acknowledged_alerts')
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='resolved_alerts')
    metadata = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'system_alerts'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.title} ({self.severity})"

class BackupJob(models.Model):
    """Backup job configurations and schedules"""
    
    BACKUP_TYPES = [
        ('database', 'Database Backup'),
        ('files', 'File System Backup'),
        ('configuration', 'Configuration Backup'),
        ('logs', 'Log Files Backup'),
        ('full_system', 'Full System Backup'),
    ]
    
    STATUS_CHOICES = [
        ('scheduled', 'Scheduled'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    FREQUENCY_CHOICES = [
        ('hourly', 'Hourly'),
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('manual', 'Manual'),
    ]
    
    name = models.CharField(max_length=255)
    backup_type = models.CharField(max_length=20, choices=BACKUP_TYPES)
    description = models.TextField(blank=True)
    source_path = models.TextField()
    destination_path = models.TextField()
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES)
    schedule_time = models.TimeField(null=True, blank=True)
    retention_days = models.IntegerField(default=30)
    is_enabled = models.BooleanField(default=True)
    compression_enabled = models.BooleanField(default=True)
    encryption_enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    configuration = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'backup_jobs'
    
    def __str__(self):
        return f"{self.name} ({self.frequency})"

class BackupExecution(models.Model):
    """Backup execution logs"""
    
    STATUS_CHOICES = [
        ('started', 'Started'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    backup_job = models.ForeignKey(BackupJob, on_delete=models.CASCADE, related_name='executions')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='started')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration = models.DurationField(null=True, blank=True)
    backup_size = models.BigIntegerField(null=True, blank=True)  # in bytes
    files_count = models.IntegerField(null=True, blank=True)
    backup_path = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    logs = models.TextField(blank=True)
    checksum = models.CharField(max_length=64, blank=True)
    metadata = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'backup_executions'
        ordering = ['-started_at']
    
    def __str__(self):
        return f"{self.backup_job.name} - {self.started_at}"

class PerformanceMetric(models.Model):
    """Performance metrics for system optimization"""
    
    METRIC_CATEGORIES = [
        ('system', 'System Performance'),
        ('application', 'Application Performance'),
        ('database', 'Database Performance'),
        ('network', 'Network Performance'),
        ('user_experience', 'User Experience'),
    ]
    
    category = models.CharField(max_length=20, choices=METRIC_CATEGORIES)
    metric_name = models.CharField(max_length=100)
    value = models.FloatField()
    unit = models.CharField(max_length=20, blank=True)
    component = models.ForeignKey(InfrastructureComponent, on_delete=models.CASCADE, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    tags = models.JSONField(default=dict)
    metadata = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'performance_metrics'
        indexes = [
            models.Index(fields=['category', 'timestamp']),
            models.Index(fields=['metric_name', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.metric_name}: {self.value} {self.unit}"

class DisasterRecoveryPlan(models.Model):
    """Disaster recovery plans and procedures"""
    
    PLAN_TYPES = [
        ('data_recovery', 'Data Recovery'),
        ('system_recovery', 'System Recovery'),
        ('network_recovery', 'Network Recovery'),
        ('application_recovery', 'Application Recovery'),
        ('full_site_recovery', 'Full Site Recovery'),
    ]
    
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('approved', 'Approved'),
        ('active', 'Active'),
        ('outdated', 'Outdated'),
        ('archived', 'Archived'),
    ]
    
    name = models.CharField(max_length=255)
    plan_type = models.CharField(max_length=20, choices=PLAN_TYPES)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    priority = models.IntegerField(default=1)  # 1=highest, 5=lowest
    rto = models.IntegerField(help_text="Recovery Time Objective (minutes)")
    rpo = models.IntegerField(help_text="Recovery Point Objective (minutes)")
    procedures = models.JSONField(default=list)
    contacts = models.JSONField(default=list)
    resources_required = models.JSONField(default=list)
    dependencies = models.JSONField(default=list)
    testing_schedule = models.CharField(max_length=50, blank=True)
    last_tested = models.DateTimeField(null=True, blank=True)
    last_updated = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_dr_plans')
    
    class Meta:
        db_table = 'disaster_recovery_plans'
    
    def __str__(self):
        return f"{self.name} ({self.plan_type})"

class DisasterRecoveryTest(models.Model):
    """Disaster recovery test executions"""
    
    TEST_TYPES = [
        ('tabletop', 'Tabletop Exercise'),
        ('walkthrough', 'Walkthrough Test'),
        ('simulation', 'Simulation Test'),
        ('parallel', 'Parallel Test'),
        ('full_interruption', 'Full Interruption Test'),
    ]
    
    STATUS_CHOICES = [
        ('planned', 'Planned'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    dr_plan = models.ForeignKey(DisasterRecoveryPlan, on_delete=models.CASCADE, related_name='tests')
    test_type = models.CharField(max_length=20, choices=TEST_TYPES)
    test_name = models.CharField(max_length=255)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='planned')
    scheduled_date = models.DateTimeField()
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration = models.DurationField(null=True, blank=True)
    objectives = models.JSONField(default=list)
    results = models.TextField(blank=True)
    issues_found = models.JSONField(default=list)
    recommendations = models.TextField(blank=True)
    participants = models.ManyToManyField(User, related_name='dr_tests')
    test_lead = models.ForeignKey(User, on_delete=models.CASCADE, related_name='led_dr_tests')
    
    class Meta:
        db_table = 'disaster_recovery_tests'
        ordering = ['-scheduled_date']
    
    def __str__(self):
        return f"{self.test_name} - {self.scheduled_date.date()}"

class MaintenanceWindow(models.Model):
    """Planned maintenance windows"""
    
    MAINTENANCE_TYPES = [
        ('security_updates', 'Security Updates'),
        ('system_updates', 'System Updates'),
        ('hardware_maintenance', 'Hardware Maintenance'),
        ('configuration_changes', 'Configuration Changes'),
        ('backup_testing', 'Backup Testing'),
        ('dr_testing', 'DR Testing'),
        ('performance_tuning', 'Performance Tuning'),
    ]
    
    STATUS_CHOICES = [
        ('scheduled', 'Scheduled'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
        ('failed', 'Failed'),
    ]
    
    title = models.CharField(max_length=255)
    maintenance_type = models.CharField(max_length=25, choices=MAINTENANCE_TYPES)
    description = models.TextField()
    components = models.ManyToManyField(InfrastructureComponent, related_name='maintenance_windows')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='scheduled')
    scheduled_start = models.DateTimeField()
    scheduled_end = models.DateTimeField()
    actual_start = models.DateTimeField(null=True, blank=True)
    actual_end = models.DateTimeField(null=True, blank=True)
    impact_description = models.TextField()
    rollback_plan = models.TextField(blank=True)
    assigned_to = models.ForeignKey(User, on_delete=models.CASCADE)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_maintenance')
    notification_sent = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'maintenance_windows'
        ordering = ['scheduled_start']
    
    def __str__(self):
        return f"{self.title} - {self.scheduled_start.date()}"