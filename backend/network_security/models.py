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
        return f"{self.title} ({self.severity})"

# Network Topology and Visualization Models

class NetworkTopology(models.Model):
    """Network topology mapping and visualization"""
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    network_range = models.CharField(max_length=255)
    discovered_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    topology_data = models.JSONField(default=dict)  # Stores network graph data
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    class Meta:
        verbose_name_plural = "Network Topologies"
        db_table = 'network_topologies'
    
    def __str__(self):
        return f"Topology: {self.name}"

class NetworkNode(models.Model):
    """Individual network nodes in topology"""
    
    NODE_TYPES = [
        ('host', 'Host'),
        ('router', 'Router'),
        ('switch', 'Switch'),
        ('firewall', 'Firewall'),
        ('server', 'Server'),
        ('workstation', 'Workstation'),
        ('unknown', 'Unknown'),
    ]
    
    topology = models.ForeignKey(NetworkTopology, on_delete=models.CASCADE, related_name='nodes')
    ip_address = models.GenericIPAddressField()
    hostname = models.CharField(max_length=255, blank=True)
    mac_address = models.CharField(max_length=17, blank=True)
    node_type = models.CharField(max_length=20, choices=NODE_TYPES, default='unknown')
    os_fingerprint = models.CharField(max_length=255, blank=True)
    position_x = models.FloatField(default=0.0)  # For visualization
    position_y = models.FloatField(default=0.0)
    is_gateway = models.BooleanField(default=False)
    last_seen = models.DateTimeField(auto_now=True)
    metadata = models.JSONField(default=dict)
    
    class Meta:
        unique_together = ['topology', 'ip_address']
        db_table = 'network_nodes'
    
    def __str__(self):
        return f"{self.ip_address} ({self.node_type})"

class NetworkConnection(models.Model):
    """Network connections between nodes"""
    
    CONNECTION_TYPES = [
        ('direct', 'Direct Connection'),
        ('routed', 'Routed Connection'),
        ('vpn', 'VPN Connection'),
        ('wireless', 'Wireless Connection'),
    ]
    
    topology = models.ForeignKey(NetworkTopology, on_delete=models.CASCADE, related_name='connections')
    source_node = models.ForeignKey(NetworkNode, on_delete=models.CASCADE, related_name='outgoing_connections')
    destination_node = models.ForeignKey(NetworkNode, on_delete=models.CASCADE, related_name='incoming_connections')
    connection_type = models.CharField(max_length=20, choices=CONNECTION_TYPES, default='direct')
    latency = models.FloatField(null=True, blank=True)  # in milliseconds
    bandwidth = models.IntegerField(null=True, blank=True)  # in Mbps
    last_seen = models.DateTimeField(auto_now=True)
    metadata = models.JSONField(default=dict)
    
    class Meta:
        unique_together = ['topology', 'source_node', 'destination_node']
        db_table = 'network_connections'
    
    def __str__(self):
        return f"{self.source_node.ip_address} -> {self.destination_node.ip_address}"

# Intrusion Detection System Models

class IntrusionDetectionRule(models.Model):
    """IDS rules for pattern matching and anomaly detection"""
    
    RULE_TYPES = [
        ('signature', 'Signature-based'),
        ('anomaly', 'Anomaly-based'),
        ('heuristic', 'Heuristic-based'),
        ('behavioral', 'Behavioral Analysis'),
    ]
    
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]
    
    name = models.CharField(max_length=255)
    description = models.TextField()
    rule_type = models.CharField(max_length=20, choices=RULE_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    pattern = models.TextField()  # Pattern to match
    action = models.CharField(max_length=50, default='alert')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'intrusion_detection_rules'
    
    def __str__(self):
        return f"{self.name} ({self.rule_type})"

class TrafficPattern(models.Model):
    """Network traffic patterns for analysis"""
    
    PATTERN_TYPES = [
        ('normal', 'Normal Traffic'),
        ('suspicious', 'Suspicious Activity'),
        ('malicious', 'Malicious Traffic'),
        ('ddos', 'DDoS Attack'),
        ('port_scan', 'Port Scanning'),
        ('brute_force', 'Brute Force Attack'),
        ('data_exfiltration', 'Data Exfiltration'),
    ]
    
    pattern_type = models.CharField(max_length=20, choices=PATTERN_TYPES)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    source_port = models.IntegerField()
    destination_port = models.IntegerField()
    protocol = models.CharField(max_length=10)
    packet_count = models.IntegerField(default=1)
    byte_count = models.BigIntegerField(default=0)
    duration = models.DurationField()
    detected_at = models.DateTimeField(auto_now_add=True)
    confidence_score = models.FloatField(default=0.0)  # 0.0 to 1.0
    metadata = models.JSONField(default=dict)
    
    class Meta:
        indexes = [
            models.Index(fields=['source_ip', 'detected_at']),
            models.Index(fields=['destination_ip', 'detected_at']),
            models.Index(fields=['pattern_type', 'detected_at']),
        ]
        db_table = 'traffic_patterns'
    
    def __str__(self):
        return f"{self.pattern_type}: {self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}"

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
