"""
SIEM (Security Information and Event Management) Models
"""
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import json

class LogSource(models.Model):
    """
    Log sources for centralized logging
    """
    
    SOURCE_TYPES = [
        ('syslog', 'Syslog'),
        ('windows_event', 'Windows Event Log'),
        ('linux_audit', 'Linux Audit Log'),
        ('application', 'Application Log'),
        ('network_device', 'Network Device'),
        ('firewall', 'Firewall'),
        ('ids_ips', 'IDS/IPS'),
        ('database', 'Database'),
        ('web_server', 'Web Server'),
        ('custom', 'Custom Source'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('error', 'Error'),
        ('maintenance', 'Maintenance'),
    ]
    
    name = models.CharField(max_length=255)
    source_type = models.CharField(max_length=20, choices=SOURCE_TYPES)
    host = models.CharField(max_length=255)
    port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=20, default='tcp')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    
    # Authentication
    username = models.CharField(max_length=100, blank=True)
    password = models.CharField(max_length=255, blank=True)
    api_key = models.CharField(max_length=500, blank=True)
    
    # Configuration
    log_path = models.CharField(max_length=500, blank=True)
    log_format = models.CharField(max_length=50, default='json')
    collection_interval = models.IntegerField(default=60)  # seconds
    retention_days = models.IntegerField(default=90)
    
    # Metadata
    description = models.TextField(blank=True)
    tags = models.JSONField(default=list)
    configuration = models.JSONField(default=dict)
    last_collection = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'log_sources'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.source_type})"

class SecurityEvent(models.Model):
    """
    Security events from various sources
    """
    
    EVENT_TYPES = [
        ('authentication', 'Authentication'),
        ('authorization', 'Authorization'),
        ('access', 'Access Control'),
        ('network', 'Network Activity'),
        ('system', 'System Event'),
        ('application', 'Application Event'),
        ('security', 'Security Incident'),
        ('policy', 'Policy Violation'),
        ('anomaly', 'Anomaly Detection'),
        ('threat', 'Threat Detection'),
    ]
    
    SEVERITY_LEVELS = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]
    
    STATUS_CHOICES = [
        ('new', 'New'),
        ('investigating', 'Investigating'),
        ('confirmed', 'Confirmed'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
        ('suppressed', 'Suppressed'),
    ]
    
    # Event identification
    event_id = models.CharField(max_length=100, unique=True)
    event_type = models.CharField(max_length=20, choices=EVENT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    
    # Source information
    log_source = models.ForeignKey(LogSource, on_delete=models.CASCADE, related_name='events')
    source_host = models.CharField(max_length=255)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    source_user = models.CharField(max_length=100, blank=True)
    
    # Event details
    timestamp = models.DateTimeField()
    message = models.TextField()
    raw_data = models.TextField(blank=True)
    
    # Classification
    category = models.CharField(max_length=50)
    subcategory = models.CharField(max_length=50, blank=True)
    classification = models.JSONField(default=dict)
    
    # Impact assessment
    affected_assets = models.JSONField(default=list)
    impact_score = models.FloatField(default=0.0)
    confidence = models.FloatField(default=0.0)
    
    # Response
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    response_actions = models.JSONField(default=list)
    resolution_notes = models.TextField(blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    # Correlation
    correlation_id = models.CharField(max_length=100, blank=True)
    related_events = models.ManyToManyField('self', blank=True, symmetrical=False)
    
    # Metadata
    tags = models.JSONField(default=list)
    enrichment_data = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'security_events'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type', 'severity']),
            models.Index(fields=['timestamp', 'status']),
            models.Index(fields=['source_host', 'timestamp']),
            models.Index(fields=['correlation_id']),
        ]
    
    def __str__(self):
        return f"{self.event_id} - {self.event_type} ({self.severity})"

class CorrelationRule(models.Model):
    """
    Correlation rules for event analysis
    """
    
    RULE_TYPES = [
        ('pattern', 'Pattern Matching'),
        ('threshold', 'Threshold-based'),
        ('sequence', 'Sequence Analysis'),
        ('statistical', 'Statistical Analysis'),
        ('behavioral', 'Behavioral Analysis'),
        ('temporal', 'Time-based'),
    ]
    
    name = models.CharField(max_length=255)
    rule_type = models.CharField(max_length=20, choices=RULE_TYPES)
    description = models.TextField()
    is_active = models.BooleanField(default=True)
    
    # Rule conditions
    conditions = models.JSONField(default=dict)
    time_window = models.IntegerField(default=300)  # seconds
    threshold = models.IntegerField(default=1)
    
    # Actions
    actions = models.JSONField(default=list)
    severity_mapping = models.JSONField(default=dict)
    
    # Performance
    priority = models.IntegerField(default=5)  # 1=highest, 10=lowest
    execution_count = models.IntegerField(default=0)
    last_executed = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    tags = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'correlation_rules'
        ordering = ['priority', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.rule_type})"

class AlertRule(models.Model):
    """
    Alert rules for automated alerting
    """
    
    ALERT_TYPES = [
        ('email', 'Email Alert'),
        ('sms', 'SMS Alert'),
        ('webhook', 'Webhook'),
        ('slack', 'Slack Notification'),
        ('pagerduty', 'PagerDuty'),
        ('jira', 'Jira Ticket'),
        ('soar', 'SOAR Integration'),
    ]
    
    name = models.CharField(max_length=255)
    description = models.TextField()
    is_active = models.BooleanField(default=True)
    
    # Trigger conditions
    trigger_conditions = models.JSONField(default=dict)
    severity_threshold = models.CharField(max_length=10, default='medium')
    time_window = models.IntegerField(default=300)  # seconds
    cooldown_period = models.IntegerField(default=3600)  # seconds
    
    # Alert configuration
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPES)
    recipients = models.JSONField(default=list)
    template = models.TextField(blank=True)
    
    # Escalation
    escalation_rules = models.JSONField(default=dict)
    max_alerts_per_window = models.IntegerField(default=10)
    
    # Statistics
    alert_count = models.IntegerField(default=0)
    last_alert = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    tags = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'alert_rules'
        ordering = ['name']
    
    def __str__(self):
        return f"{self.name} ({self.alert_type})"

class Alert(models.Model):
    """
    Generated alerts from rules
    """
    
    ALERT_STATUS = [
        ('new', 'New'),
        ('acknowledged', 'Acknowledged'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('escalated', 'Escalated'),
        ('suppressed', 'Suppressed'),
    ]
    
    alert_id = models.CharField(max_length=100, unique=True)
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=10)
    status = models.CharField(max_length=20, choices=ALERT_STATUS, default='new')
    
    # Source
    alert_rule = models.ForeignKey(AlertRule, on_delete=models.CASCADE, related_name='alerts')
    correlation_rule = models.ForeignKey(CorrelationRule, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Context
    events = models.ManyToManyField(SecurityEvent, related_name='alerts')
    affected_assets = models.JSONField(default=list)
    impact_assessment = models.JSONField(default=dict)
    
    # Response
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    response_actions = models.JSONField(default=list)
    resolution_notes = models.TextField(blank=True)
    
    # Timeline
    created_at = models.DateTimeField(auto_now_add=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    escalated_at = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    tags = models.JSONField(default=list)
    enrichment_data = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'alerts'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['created_at', 'status']),
        ]
    
    def __str__(self):
        return f"{self.alert_id} - {self.title} ({self.severity})"

class SOARIntegration(models.Model):
    """
    SOAR (Security Orchestration, Automation and Response) platform integration
    """
    
    PLATFORM_TYPES = [
        ('splunk_soar', 'Splunk SOAR'),
        ('ibm_resilient', 'IBM Resilient'),
        ('swimlane', 'Swimlane'),
        ('demisto', 'Demisto'),
        ('custom', 'Custom SOAR'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('error', 'Error'),
        ('maintenance', 'Maintenance'),
    ]
    
    name = models.CharField(max_length=255)
    platform_type = models.CharField(max_length=20, choices=PLATFORM_TYPES)
    host = models.CharField(max_length=255)
    port = models.IntegerField(default=443)
    api_endpoint = models.URLField()
    
    # Authentication
    username = models.CharField(max_length=100, blank=True)
    password = models.CharField(max_length=255, blank=True)
    api_key = models.CharField(max_length=500, blank=True)
    auth_token = models.CharField(max_length=500, blank=True)
    
    # Configuration
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    playbook_mappings = models.JSONField(default=dict)
    workflow_mappings = models.JSONField(default=dict)
    
    # Statistics
    total_incidents = models.IntegerField(default=0)
    successful_actions = models.IntegerField(default=0)
    failed_actions = models.IntegerField(default=0)
    last_sync = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    description = models.TextField(blank=True)
    configuration = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'soar_integrations'
    
    def __str__(self):
        return f"{self.name} ({self.platform_type})"

class SOARAction(models.Model):
    """
    SOAR automated response actions
    """
    
    ACTION_TYPES = [
        ('isolate_host', 'Isolate Host'),
        ('block_ip', 'Block IP Address'),
        ('quarantine_file', 'Quarantine File'),
        ('disable_user', 'Disable User Account'),
        ('patch_system', 'Apply Security Patch'),
        ('collect_evidence', 'Collect Evidence'),
        ('notify_team', 'Notify Security Team'),
        ('create_ticket', 'Create Support Ticket'),
        ('run_playbook', 'Execute SOAR Playbook'),
        ('custom', 'Custom Action'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='soar_actions')
    soar_integration = models.ForeignKey(SOARIntegration, on_delete=models.CASCADE)
    
    action_type = models.CharField(max_length=20, choices=ACTION_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Action details
    action_parameters = models.JSONField(default=dict)
    description = models.TextField()
    
    # Execution
    initiated_by = models.ForeignKey(User, on_delete=models.CASCADE)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration = models.DurationField(null=True, blank=True)
    
    # Results
    result_data = models.JSONField(default=dict)
    error_message = models.TextField(blank=True)
    success = models.BooleanField(default=False)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'soar_actions'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.action_type} - {self.alert.alert_id} ({self.status})"

class SIEMDashboard(models.Model):
    """
    Custom SIEM dashboards and visualizations
    """
    
    name = models.CharField(max_length=255)
    description = models.TextField()
    is_public = models.BooleanField(default=False)
    
    # Dashboard configuration
    layout = models.JSONField(default=dict)
    widgets = models.JSONField(default=list)
    filters = models.JSONField(default=dict)
    time_range = models.JSONField(default=dict)
    
    # Permissions
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    shared_with = models.ManyToManyField(User, related_name='shared_dashboards', blank=True)
    
    # Usage
    view_count = models.IntegerField(default=0)
    last_viewed = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    tags = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'siem_dashboards'
        ordering = ['name']
    
    def __str__(self):
        return self.name

class SIEMReport(models.Model):
    """
    SIEM reports and analytics
    """
    
    REPORT_TYPES = [
        ('daily', 'Daily Report'),
        ('weekly', 'Weekly Report'),
        ('monthly', 'Monthly Report'),
        ('incident', 'Incident Report'),
        ('compliance', 'Compliance Report'),
        ('threat', 'Threat Analysis Report'),
        ('custom', 'Custom Report'),
    ]
    
    STATUS_CHOICES = [
        ('scheduled', 'Scheduled'),
        ('generating', 'Generating'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    name = models.CharField(max_length=255)
    report_type = models.CharField(max_length=20, choices=REPORT_TYPES)
    description = models.TextField()
    
    # Report configuration
    parameters = models.JSONField(default=dict)
    schedule = models.JSONField(default=dict)
    recipients = models.JSONField(default=list)
    
    # Generation
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='scheduled')
    generated_at = models.DateTimeField(null=True, blank=True)
    file_path = models.CharField(max_length=500, blank=True)
    file_size = models.IntegerField(null=True, blank=True)
    
    # Content
    summary = models.TextField(blank=True)
    statistics = models.JSONField(default=dict)
    findings = models.JSONField(default=list)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'siem_reports'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.report_type})"