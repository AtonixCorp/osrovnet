"""
Security Analytics Models for ML-based Threat Detection
"""
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import json

class AnomalyDetectionModel(models.Model):
    """
    Machine Learning models for anomaly detection
    """
    
    MODEL_TYPES = [
        ('isolation_forest', 'Isolation Forest'),
        ('one_class_svm', 'One-Class SVM'),
        ('lstm_autoencoder', 'LSTM Autoencoder'),
        ('behavioral_analysis', 'Behavioral Analysis'),
        ('network_traffic', 'Network Traffic Analysis'),
        ('user_behavior', 'User Behavior Analytics'),
    ]
    
    STATUS_CHOICES = [
        ('training', 'Training'),
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('retraining', 'Retraining'),
        ('error', 'Error'),
    ]
    
    name = models.CharField(max_length=255)
    model_type = models.CharField(max_length=30, choices=MODEL_TYPES)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='training')
    model_file = models.CharField(max_length=500, blank=True)  # Path to serialized model
    feature_columns = models.JSONField(default=list)
    training_data_size = models.IntegerField(default=0)
    accuracy_score = models.FloatField(null=True, blank=True)
    precision_score = models.FloatField(null=True, blank=True)
    recall_score = models.FloatField(null=True, blank=True)
    f1_score = models.FloatField(null=True, blank=True)
    false_positive_rate = models.FloatField(null=True, blank=True)
    last_trained = models.DateTimeField(null=True, blank=True)
    last_evaluated = models.DateTimeField(null=True, blank=True)
    hyperparameters = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'anomaly_detection_models'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.model_type})"

class BehavioralProfile(models.Model):
    """
    User and entity behavioral profiles for anomaly detection
    """
    
    ENTITY_TYPES = [
        ('user', 'User'),
        ('host', 'Host/Device'),
        ('service', 'Service/Application'),
        ('network_segment', 'Network Segment'),
    ]
    
    entity_type = models.CharField(max_length=20, choices=ENTITY_TYPES)
    entity_id = models.CharField(max_length=255)  # User ID, IP address, etc.
    entity_name = models.CharField(max_length=255)
    
    # Behavioral metrics
    login_patterns = models.JSONField(default=dict)  # Time patterns, locations, etc.
    network_activity = models.JSONField(default=dict)  # Traffic patterns, protocols
    file_access_patterns = models.JSONField(default=dict)  # File access behavior
    application_usage = models.JSONField(default=dict)  # Application usage patterns
    risk_score = models.FloatField(default=0.0)  # Current risk score
    baseline_established = models.BooleanField(default=False)
    
    # Timestamps
    profile_start = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    last_activity = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    metadata = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'behavioral_profiles'
        unique_together = ['entity_type', 'entity_id']
        indexes = [
            models.Index(fields=['entity_type', 'risk_score']),
            models.Index(fields=['last_activity']),
        ]
    
    def __str__(self):
        return f"{self.entity_type}: {self.entity_name}"

class AnomalyDetection(models.Model):
    """
    Detected anomalies from ML models
    """
    
    ANOMALY_TYPES = [
        ('behavioral', 'Behavioral Anomaly'),
        ('network_traffic', 'Network Traffic Anomaly'),
        ('access_pattern', 'Access Pattern Anomaly'),
        ('data_exfiltration', 'Data Exfiltration'),
        ('lateral_movement', 'Lateral Movement'),
        ('privilege_escalation', 'Privilege Escalation'),
        ('unusual_login', 'Unusual Login Pattern'),
        ('insider_threat', 'Insider Threat Indicator'),
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
        ('false_positive', 'False Positive'),
        ('resolved', 'Resolved'),
        ('suppressed', 'Suppressed'),
    ]
    
    model = models.ForeignKey(AnomalyDetectionModel, on_delete=models.CASCADE, related_name='detections')
    behavioral_profile = models.ForeignKey(BehavioralProfile, on_delete=models.CASCADE, null=True, blank=True)
    
    anomaly_type = models.CharField(max_length=30, choices=ANOMALY_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    
    # Detection details
    anomaly_score = models.FloatField()  # Anomaly score from ML model
    confidence = models.FloatField()  # Confidence in detection
    threshold = models.FloatField()  # Threshold used for detection
    
    # Context information
    entity_type = models.CharField(max_length=20)
    entity_id = models.CharField(max_length=255)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    user_id = models.CharField(max_length=255, blank=True)
    
    # Event details
    event_data = models.JSONField(default=dict)  # Raw event data
    features_used = models.JSONField(default=list)  # Features used in detection
    description = models.TextField()
    recommendations = models.TextField(blank=True)
    
    # Timestamps
    detected_at = models.DateTimeField(auto_now_add=True)
    event_timestamp = models.DateTimeField()
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    # Assignment and notes
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    analyst_notes = models.TextField(blank=True)
    
    # Correlation
    related_detections = models.ManyToManyField('self', blank=True, symmetrical=False)
    
    class Meta:
        db_table = 'anomaly_detections'
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['anomaly_type', 'detected_at']),
            models.Index(fields=['entity_type', 'entity_id']),
        ]
    
    def __str__(self):
        return f"{self.anomaly_type} - {self.entity_id} ({self.severity})"

class MLTrainingDataset(models.Model):
    """
    Training datasets for ML models
    """
    
    DATASET_TYPES = [
        ('network_traffic', 'Network Traffic'),
        ('user_behavior', 'User Behavior'),
        ('system_logs', 'System Logs'),
        ('security_events', 'Security Events'),
        ('threat_intelligence', 'Threat Intelligence'),
    ]
    
    name = models.CharField(max_length=255)
    dataset_type = models.CharField(max_length=30, choices=DATASET_TYPES)
    description = models.TextField()
    file_path = models.CharField(max_length=500)
    size_mb = models.FloatField()
    record_count = models.IntegerField()
    feature_count = models.IntegerField()
    label_column = models.CharField(max_length=100, blank=True)
    date_from = models.DateTimeField()
    date_to = models.DateTimeField()
    is_labeled = models.BooleanField(default=False)
    preprocessing_config = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'ml_training_datasets'
    
    def __str__(self):
        return f"{self.name} ({self.dataset_type})"

class ThreatHuntingCampaign(models.Model):
    """
    Advanced threat hunting campaigns using ML insights
    """
    
    CAMPAIGN_STATUS = [
        ('planned', 'Planned'),
        ('active', 'Active'),
        ('paused', 'Paused'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    
    name = models.CharField(max_length=255)
    description = models.TextField()
    hypothesis = models.TextField()
    status = models.CharField(max_length=20, choices=CAMPAIGN_STATUS, default='planned')
    
    # ML-driven hunting
    detection_models = models.ManyToManyField(AnomalyDetectionModel, blank=True)
    target_entities = models.JSONField(default=list)  # Entities to focus on
    hunting_queries = models.JSONField(default=list)  # Queries to execute
    ml_insights = models.JSONField(default=dict)  # Insights from ML models
    
    # Campaign details
    start_date = models.DateTimeField()
    end_date = models.DateTimeField(null=True, blank=True)
    hunter = models.ForeignKey(User, on_delete=models.CASCADE)
    team_members = models.ManyToManyField(User, related_name='hunting_campaigns', blank=True)
    
    # Results
    findings = models.TextField(blank=True)
    indicators_found = models.JSONField(default=list)
    threats_identified = models.IntegerField(default=0)
    false_positives = models.IntegerField(default=0)
    
    # Metadata
    tags = models.JSONField(default=list)
    priority = models.IntegerField(default=3)  # 1=highest, 5=lowest
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'threat_hunting_campaigns'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.status})"

class SecurityMetric(models.Model):
    """
    Security metrics and KPIs for analytics
    """
    
    METRIC_CATEGORIES = [
        ('detection', 'Detection Metrics'),
        ('response', 'Response Metrics'),
        ('prevention', 'Prevention Metrics'),
        ('risk', 'Risk Metrics'),
        ('compliance', 'Compliance Metrics'),
    ]
    
    category = models.CharField(max_length=20, choices=METRIC_CATEGORIES)
    metric_name = models.CharField(max_length=100)
    value = models.FloatField()
    unit = models.CharField(max_length=20)
    target_value = models.FloatField(null=True, blank=True)
    threshold_warning = models.FloatField(null=True, blank=True)
    threshold_critical = models.FloatField(null=True, blank=True)
    
    # Context
    entity_type = models.CharField(max_length=50, blank=True)
    entity_id = models.CharField(max_length=255, blank=True)
    time_period = models.CharField(max_length=50)  # 'hourly', 'daily', 'weekly', etc.
    
    # Timestamps
    timestamp = models.DateTimeField(auto_now_add=True)
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    
    # Metadata
    calculation_method = models.TextField(blank=True)
    data_sources = models.JSONField(default=list)
    metadata = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'security_metrics'
        indexes = [
            models.Index(fields=['category', 'timestamp']),
            models.Index(fields=['metric_name', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.metric_name}: {self.value} {self.unit}"

class InsiderThreatIndicator(models.Model):
    """
    Insider threat indicators and risk factors
    """
    
    INDICATOR_TYPES = [
        ('data_access', 'Unusual Data Access'),
        ('file_download', 'Large File Downloads'),
        ('after_hours', 'After Hours Activity'),
        ('privilege_usage', 'Privilege Misuse'),
        ('policy_violation', 'Policy Violation'),
        ('behavioral_change', 'Behavioral Change'),
        ('external_communication', 'External Communication'),
        ('system_bypass', 'System Bypass Attempt'),
    ]
    
    RISK_LEVELS = [
        ('very_high', 'Very High'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('very_low', 'Very Low'),
    ]
    
    behavioral_profile = models.ForeignKey(BehavioralProfile, on_delete=models.CASCADE)
    indicator_type = models.CharField(max_length=30, choices=INDICATOR_TYPES)
    risk_level = models.CharField(max_length=10, choices=RISK_LEVELS)
    
    # Indicator details
    description = models.TextField()
    evidence = models.JSONField(default=dict)
    risk_score = models.FloatField()
    confidence = models.FloatField()
    
    # Context
    event_count = models.IntegerField(default=1)
    first_observed = models.DateTimeField()
    last_observed = models.DateTimeField()
    
    # Investigation
    is_investigated = models.BooleanField(default=False)
    investigation_notes = models.TextField(blank=True)
    is_confirmed = models.BooleanField(default=False)
    false_positive = models.BooleanField(default=False)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'insider_threat_indicators'
        ordering = ['-risk_score', '-created_at']
    
    def __str__(self):
        return f"{self.indicator_type} - {self.behavioral_profile.entity_name} ({self.risk_level})"