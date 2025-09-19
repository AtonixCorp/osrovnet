from django.db import models
from django.contrib.auth.models import User
from django.core.validators import validate_ipv4_address, validate_ipv6_address
from django.utils import timezone
import json

class NetworkTarget(models.Model):
    """Model to store network scan targets"""
    SCAN_TYPES = [
        ('ping', 'Ping Sweep'),
        ('tcp', 'TCP Scan'),
        ('udp', 'UDP Scan'),
        ('syn', 'SYN Scan'),
        ('comprehensive', 'Comprehensive Scan'),
    ]
    
    name = models.CharField(max_length=255, help_text="Target name or description")
    target = models.CharField(max_length=255, help_text="IP address, range, or hostname")
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES, default='tcp')
    ports = models.TextField(default="1-1000", help_text="Port range (e.g., 1-1000, 80,443,22)")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'network_targets'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.target})"

class NetworkScan(models.Model):
    """Model to store network scan results"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    target = models.ForeignKey(NetworkTarget, on_delete=models.CASCADE, related_name='scans')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration = models.DurationField(null=True, blank=True)
    hosts_discovered = models.IntegerField(default=0)
    ports_scanned = models.IntegerField(default=0)
    vulnerabilities_found = models.IntegerField(default=0)
    scan_output = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)
    initiated_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'network_scans'
        ordering = ['-started_at']
    
    def __str__(self):
        return f"Scan {self.id} - {self.target.name} ({self.status})"
    
    def mark_completed(self):
        self.status = 'completed'
        self.completed_at = timezone.now()
        if self.started_at:
            self.duration = self.completed_at - self.started_at
        self.save()

class DiscoveredHost(models.Model):
    """Model to store discovered network hosts"""
    HOST_STATES = [
        ('up', 'Up'),
        ('down', 'Down'),
        ('unknown', 'Unknown'),
        ('filtered', 'Filtered'),
    ]
    
    scan = models.ForeignKey(NetworkScan, on_delete=models.CASCADE, related_name='hosts')
    ip_address = models.GenericIPAddressField()
    hostname = models.CharField(max_length=255, blank=True)
    mac_address = models.CharField(max_length=17, blank=True)
    state = models.CharField(max_length=20, choices=HOST_STATES, default='unknown')
    os_detection = models.JSONField(default=dict, blank=True)
    last_seen = models.DateTimeField(auto_now=True)
    response_time = models.FloatField(null=True, blank=True, help_text="Response time in milliseconds")
    
    class Meta:
        db_table = 'discovered_hosts'
        unique_together = ['scan', 'ip_address']
        ordering = ['ip_address']
    
    def __str__(self):
        return f"{self.ip_address} ({self.state})"

class DiscoveredPort(models.Model):
    """Model to store discovered ports on hosts"""
    PORT_STATES = [
        ('open', 'Open'),
        ('closed', 'Closed'),
        ('filtered', 'Filtered'),
        ('unfiltered', 'Unfiltered'),
        ('open|filtered', 'Open|Filtered'),
        ('closed|filtered', 'Closed|Filtered'),
    ]
    
    PROTOCOLS = [
        ('tcp', 'TCP'),
        ('udp', 'UDP'),
    ]
    
    host = models.ForeignKey(DiscoveredHost, on_delete=models.CASCADE, related_name='ports')
    port_number = models.IntegerField()
    protocol = models.CharField(max_length=3, choices=PROTOCOLS, default='tcp')
    state = models.CharField(max_length=20, choices=PORT_STATES, default='closed')
    service_name = models.CharField(max_length=255, blank=True)
    service_version = models.CharField(max_length=255, blank=True)
    service_info = models.JSONField(default=dict, blank=True)
    banner = models.TextField(blank=True)
    
    class Meta:
        db_table = 'discovered_ports'
        unique_together = ['host', 'port_number', 'protocol']
        ordering = ['port_number']
    
    def __str__(self):
        return f"{self.host.ip_address}:{self.port_number}/{self.protocol} ({self.state})"

class Vulnerability(models.Model):
    """Model to store discovered vulnerabilities"""
    SEVERITY_LEVELS = [
        ('info', 'Informational'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    port = models.ForeignKey(DiscoveredPort, on_delete=models.CASCADE, related_name='vulnerabilities')
    cve_id = models.CharField(max_length=20, blank=True)
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='info')
    cvss_score = models.FloatField(null=True, blank=True)
    solution = models.TextField(blank=True)
    references = models.JSONField(default=list, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'vulnerabilities'
        ordering = ['-cvss_score', '-discovered_at']
    
    def __str__(self):
        return f"{self.cve_id or 'VULN'} - {self.title} ({self.severity})"

class NetworkTraffic(models.Model):
    """Model to store real-time network traffic data"""
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    source_port = models.IntegerField()
    destination_port = models.IntegerField()
    protocol = models.CharField(max_length=10)
    packet_size = models.IntegerField()
    flags = models.CharField(max_length=50, blank=True)
    payload_snippet = models.TextField(blank=True, max_length=500)
    
    class Meta:
        db_table = 'network_traffic'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['source_ip']),
            models.Index(fields=['destination_ip']),
            models.Index(fields=['protocol']),
        ]
    
    def __str__(self):
        return f"{self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port} ({self.protocol})"

class NetworkAlert(models.Model):
    """Model to store network security alerts"""
    ALERT_TYPES = [
        ('intrusion', 'Intrusion Attempt'),
        ('port_scan', 'Port Scan'),
        ('ddos', 'DDoS Attack'),
        ('malware', 'Malware Detection'),
        ('anomaly', 'Traffic Anomaly'),
        ('policy_violation', 'Policy Violation'),
    ]
    
    SEVERITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('new', 'New'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]
    
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    title = models.CharField(max_length=255)
    description = models.TextField()
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    related_scan = models.ForeignKey(NetworkScan, on_delete=models.SET_NULL, null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        db_table = 'network_alerts'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['alert_type']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.alert_type.title()} Alert - {self.title} ({self.severity})"
