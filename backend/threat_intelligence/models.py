"""
Threat Intelligence Models for OSROVNet
"""
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import json

class ThreatFeed(models.Model):
    """Threat intelligence feed sources"""
    
    FEED_TYPES = [
        ('misp', 'MISP Platform'),
        ('otx', 'AlienVault OTX'),
        ('virustotal', 'VirusTotal'),
        ('abuse_ch', 'Abuse.ch'),
        ('emergingthreats', 'Emerging Threats'),
        ('talos', 'Cisco Talos'),
        ('custom', 'Custom Feed'),
        ('osint', 'Open Source Intelligence'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('error', 'Error'),
        ('maintenance', 'Maintenance'),
    ]
    
    name = models.CharField(max_length=255)
    feed_type = models.CharField(max_length=20, choices=FEED_TYPES)
    url = models.URLField(blank=True)
    api_key = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    last_updated = models.DateTimeField(null=True, blank=True)
    update_interval = models.IntegerField(default=3600)  # seconds
    is_enabled = models.BooleanField(default=True)
    confidence_level = models.IntegerField(default=50)  # 0-100
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    metadata = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'threat_feeds'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.feed_type})"

class IndicatorOfCompromise(models.Model):
    """Indicators of Compromise (IOCs)"""
    
    IOC_TYPES = [
        ('ip', 'IP Address'),
        ('domain', 'Domain'),
        ('url', 'URL'),
        ('hash_md5', 'MD5 Hash'),
        ('hash_sha1', 'SHA1 Hash'),
        ('hash_sha256', 'SHA256 Hash'),
        ('email', 'Email Address'),
        ('file_path', 'File Path'),
        ('registry_key', 'Registry Key'),
        ('user_agent', 'User Agent'),
        ('certificate', 'Certificate'),
        ('mutex', 'Mutex'),
        ('yara_rule', 'YARA Rule'),
    ]
    
    THREAT_TYPES = [
        ('malware', 'Malware'),
        ('botnet', 'Botnet'),
        ('phishing', 'Phishing'),
        ('c2', 'Command & Control'),
        ('apt', 'Advanced Persistent Threat'),
        ('ransomware', 'Ransomware'),
        ('trojan', 'Trojan'),
        ('backdoor', 'Backdoor'),
        ('exploit', 'Exploit'),
        ('suspicious', 'Suspicious Activity'),
    ]
    
    SEVERITY_LEVELS = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('expired', 'Expired'),
        ('whitelist', 'Whitelisted'),
    ]
    
    value = models.TextField()  # The actual IOC value
    ioc_type = models.CharField(max_length=20, choices=IOC_TYPES)
    threat_type = models.CharField(max_length=20, choices=THREAT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    confidence = models.IntegerField(default=50)  # 0-100
    source_feed = models.ForeignKey(ThreatFeed, on_delete=models.CASCADE, related_name='iocs')
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    tags = models.JSONField(default=list)
    description = models.TextField(blank=True)
    context = models.JSONField(default=dict)  # Additional context information
    tlp = models.CharField(max_length=10, default='white')  # Traffic Light Protocol
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    
    class Meta:
        db_table = 'indicators_of_compromise'
        indexes = [
            models.Index(fields=['value', 'ioc_type']),
            models.Index(fields=['threat_type', 'severity']),
            models.Index(fields=['status', 'expires_at']),
        ]
        unique_together = ['value', 'ioc_type', 'source_feed']
    
    def __str__(self):
        return f"{self.ioc_type.upper()}: {self.value[:50]}..."

class ThreatActor(models.Model):
    """Threat actor/group information"""
    
    ACTOR_TYPES = [
        ('apt', 'Advanced Persistent Threat'),
        ('cybercriminal', 'Cybercriminal Group'),
        ('nation_state', 'Nation State'),
        ('hacktivist', 'Hacktivist'),
        ('insider', 'Insider Threat'),
        ('unknown', 'Unknown'),
    ]
    
    name = models.CharField(max_length=255)
    aliases = models.JSONField(default=list)
    actor_type = models.CharField(max_length=20, choices=ACTOR_TYPES)
    description = models.TextField(blank=True)
    country = models.CharField(max_length=100, blank=True)
    motivation = models.TextField(blank=True)
    capabilities = models.JSONField(default=list)
    targets = models.JSONField(default=list)
    ttps = models.JSONField(default=list)  # Tactics, Techniques, Procedures
    first_seen = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    confidence = models.IntegerField(default=50)
    metadata = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'threat_actors'
    
    def __str__(self):
        return self.name

class ThreatCampaign(models.Model):
    """Threat campaigns and operations"""
    
    CAMPAIGN_STATUS = [
        ('active', 'Active'),
        ('dormant', 'Dormant'),
        ('concluded', 'Concluded'),
        ('unknown', 'Unknown'),
    ]
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    threat_actor = models.ForeignKey(ThreatActor, on_delete=models.SET_NULL, null=True, blank=True)
    status = models.CharField(max_length=20, choices=CAMPAIGN_STATUS, default='unknown')
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField(null=True, blank=True)
    targets = models.JSONField(default=list)
    attack_patterns = models.JSONField(default=list)
    malware_families = models.JSONField(default=list)
    iocs = models.ManyToManyField(IndicatorOfCompromise, related_name='campaigns', blank=True)
    confidence = models.IntegerField(default=50)
    metadata = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'threat_campaigns'
    
    def __str__(self):
        return self.name

class ThreatIntelligenceReport(models.Model):
    """Threat intelligence reports and analysis"""
    
    REPORT_TYPES = [
        ('ioc', 'IOC Report'),
        ('malware', 'Malware Analysis'),
        ('campaign', 'Campaign Analysis'),
        ('actor', 'Threat Actor Profile'),
        ('vulnerability', 'Vulnerability Report'),
        ('general', 'General Intelligence'),
    ]
    
    title = models.CharField(max_length=255)
    report_type = models.CharField(max_length=20, choices=REPORT_TYPES)
    content = models.TextField()
    summary = models.TextField(blank=True)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    source = models.CharField(max_length=255, blank=True)
    confidence = models.IntegerField(default=50)
    severity = models.CharField(max_length=10, choices=IndicatorOfCompromise.SEVERITY_LEVELS)
    tlp = models.CharField(max_length=10, default='white')
    tags = models.JSONField(default=list)
    iocs = models.ManyToManyField(IndicatorOfCompromise, related_name='reports', blank=True)
    threat_actors = models.ManyToManyField(ThreatActor, related_name='reports', blank=True)
    campaigns = models.ManyToManyField(ThreatCampaign, related_name='reports', blank=True)
    published_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    metadata = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'threat_intelligence_reports'
        ordering = ['-published_at']
    
    def __str__(self):
        return self.title

class ThreatHunt(models.Model):
    """Threat hunting campaigns and results"""
    
    HUNT_STATUS = [
        ('planning', 'Planning'),
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    
    name = models.CharField(max_length=255)
    description = models.TextField()
    hypothesis = models.TextField()
    hunt_type = models.CharField(max_length=50)
    status = models.CharField(max_length=20, choices=HUNT_STATUS, default='planning')
    hunter = models.ForeignKey(User, on_delete=models.CASCADE)
    start_date = models.DateTimeField()
    end_date = models.DateTimeField(null=True, blank=True)
    data_sources = models.JSONField(default=list)
    search_queries = models.JSONField(default=list)
    findings = models.TextField(blank=True)
    iocs_discovered = models.ManyToManyField(IndicatorOfCompromise, related_name='hunts', blank=True)
    confidence = models.IntegerField(default=50)
    metadata = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'threat_hunts'
        ordering = ['-start_date']
    
    def __str__(self):
        return self.name

class ThreatMatch(models.Model):
    """Matches between IOCs and network activity"""
    
    MATCH_TYPES = [
        ('exact', 'Exact Match'),
        ('partial', 'Partial Match'),
        ('pattern', 'Pattern Match'),
        ('behavioral', 'Behavioral Match'),
    ]
    
    ACTION_STATUS = [
        ('detected', 'Detected'),
        ('investigating', 'Investigating'),
        ('confirmed', 'Confirmed Threat'),
        ('false_positive', 'False Positive'),
        ('resolved', 'Resolved'),
    ]
    
    ioc = models.ForeignKey(IndicatorOfCompromise, on_delete=models.CASCADE)
    match_type = models.CharField(max_length=20, choices=MATCH_TYPES)
    matched_value = models.TextField()
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    source_event = models.CharField(max_length=255, blank=True)  # e.g., 'network_scan', 'traffic_log'
    event_data = models.JSONField(default=dict)
    confidence = models.IntegerField(default=50)
    status = models.CharField(max_length=20, choices=ACTION_STATUS, default='detected')
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    count = models.IntegerField(default=1)
    analyst = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    notes = models.TextField(blank=True)
    
    class Meta:
        db_table = 'threat_matches'
        indexes = [
            models.Index(fields=['source_ip', 'first_seen']),
            models.Index(fields=['status', 'first_seen']),
        ]
    
    def __str__(self):
        return f"Match: {self.ioc.value} ({self.match_type})"

class ThreatResponsePlaybook(models.Model):
    """Automated threat response playbooks"""
    
    TRIGGER_TYPES = [
        ('ioc_match', 'IOC Match'),
        ('severity_threshold', 'Severity Threshold'),
        ('threat_type', 'Threat Type'),
        ('actor_match', 'Threat Actor Match'),
        ('manual', 'Manual Trigger'),
    ]
    
    name = models.CharField(max_length=255)
    description = models.TextField()
    trigger_type = models.CharField(max_length=20, choices=TRIGGER_TYPES)
    trigger_conditions = models.JSONField(default=dict)
    actions = models.JSONField(default=list)  # List of actions to execute
    is_active = models.BooleanField(default=True)
    auto_execute = models.BooleanField(default=False)
    execution_count = models.IntegerField(default=0)
    last_executed = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'threat_response_playbooks'
    
    def __str__(self):
        return self.name

class ThreatResponseExecution(models.Model):
    """Threat response execution logs"""
    
    EXECUTION_STATUS = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    playbook = models.ForeignKey(ThreatResponsePlaybook, on_delete=models.CASCADE)
    trigger_event = models.JSONField(default=dict)
    status = models.CharField(max_length=20, choices=EXECUTION_STATUS, default='pending')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    executed_actions = models.JSONField(default=list)
    results = models.JSONField(default=dict)
    errors = models.TextField(blank=True)
    executed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        db_table = 'threat_response_executions'
        ordering = ['-started_at']
    
    def __str__(self):
        return f"{self.playbook.name} - {self.started_at}"
