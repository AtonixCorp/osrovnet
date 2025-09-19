from rest_framework import serializers
from .models import (
    NetworkTarget, NetworkScan, DiscoveredHost, DiscoveredPort, 
    Vulnerability, NetworkTraffic, NetworkAlert
)

class NetworkTargetSerializer(serializers.ModelSerializer):
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    scan_count = serializers.SerializerMethodField()
    
    class Meta:
        model = NetworkTarget
        fields = [
            'id', 'name', 'target', 'scan_type', 'ports', 'created_at', 
            'updated_at', 'created_by', 'created_by_username', 'is_active', 'scan_count'
        ]
        read_only_fields = ['created_by']
    
    def get_scan_count(self, obj):
        return obj.scans.count()

class DiscoveredPortSerializer(serializers.ModelSerializer):
    vulnerability_count = serializers.SerializerMethodField()
    
    class Meta:
        model = DiscoveredPort
        fields = [
            'id', 'port_number', 'protocol', 'state', 'service_name', 
            'service_version', 'service_info', 'banner', 'vulnerability_count'
        ]
    
    def get_vulnerability_count(self, obj):
        return obj.vulnerabilities.count()

class DiscoveredHostSerializer(serializers.ModelSerializer):
    ports = DiscoveredPortSerializer(many=True, read_only=True)
    port_count = serializers.SerializerMethodField()
    vulnerability_count = serializers.SerializerMethodField()
    
    class Meta:
        model = DiscoveredHost
        fields = [
            'id', 'ip_address', 'hostname', 'mac_address', 'state', 
            'os_detection', 'last_seen', 'response_time', 'ports', 
            'port_count', 'vulnerability_count'
        ]
    
    def get_port_count(self, obj):
        return obj.ports.count()
    
    def get_vulnerability_count(self, obj):
        return sum(port.vulnerabilities.count() for port in obj.ports.all())

class NetworkScanSerializer(serializers.ModelSerializer):
    target_details = NetworkTargetSerializer(source='target', read_only=True)
    initiated_by_username = serializers.CharField(source='initiated_by.username', read_only=True)
    hosts = DiscoveredHostSerializer(many=True, read_only=True)
    duration_seconds = serializers.SerializerMethodField()
    
    class Meta:
        model = NetworkScan
        fields = [
            'id', 'target', 'target_details', 'status', 'started_at', 'completed_at', 
            'duration', 'duration_seconds', 'hosts_discovered', 'ports_scanned', 
            'vulnerabilities_found', 'error_message', 'initiated_by', 
            'initiated_by_username', 'hosts'
        ]
        read_only_fields = ['initiated_by', 'scan_output']
    
    def get_duration_seconds(self, obj):
        if obj.duration:
            return obj.duration.total_seconds()
        return None

class VulnerabilitySerializer(serializers.ModelSerializer):
    host_ip = serializers.CharField(source='port.host.ip_address', read_only=True)
    port_info = serializers.SerializerMethodField()
    
    class Meta:
        model = Vulnerability
        fields = [
            'id', 'cve_id', 'title', 'description', 'severity', 'cvss_score', 
            'solution', 'references', 'discovered_at', 'host_ip', 'port_info'
        ]
    
    def get_port_info(self, obj):
        return f"{obj.port.port_number}/{obj.port.protocol}"

class NetworkTrafficSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkTraffic
        fields = [
            'id', 'timestamp', 'source_ip', 'destination_ip', 'source_port', 
            'destination_port', 'protocol', 'packet_size', 'flags', 'payload_snippet'
        ]

class NetworkAlertSerializer(serializers.ModelSerializer):
    assigned_to_username = serializers.CharField(source='assigned_to.username', read_only=True)
    related_scan_info = serializers.SerializerMethodField()
    
    class Meta:
        model = NetworkAlert
        fields = [
            'id', 'alert_type', 'severity', 'status', 'title', 'description', 
            'source_ip', 'destination_ip', 'metadata', 'created_at', 'updated_at', 
            'assigned_to', 'assigned_to_username', 'related_scan', 'related_scan_info'
        ]
    
    def get_related_scan_info(self, obj):
        if obj.related_scan:
            return {
                'id': obj.related_scan.id,
                'target': obj.related_scan.target.name,
                'status': obj.related_scan.status
            }
        return None

class ScanStatisticsSerializer(serializers.Serializer):
    """Serializer for scan statistics"""
    total_scans = serializers.IntegerField()
    completed_scans = serializers.IntegerField()
    failed_scans = serializers.IntegerField()
    running_scans = serializers.IntegerField()
    total_hosts = serializers.IntegerField()
    total_ports = serializers.IntegerField()
    total_vulnerabilities = serializers.IntegerField()
    critical_vulnerabilities = serializers.IntegerField()
    high_vulnerabilities = serializers.IntegerField()
    recent_alerts = serializers.IntegerField()

class NetworkOverviewSerializer(serializers.Serializer):
    """Serializer for network overview dashboard"""
    active_hosts = serializers.IntegerField()
    total_ports_open = serializers.IntegerField()
    recent_scans = serializers.IntegerField()
    active_alerts = serializers.IntegerField()
    top_services = serializers.ListField()
    vulnerability_breakdown = serializers.DictField()
    traffic_summary = serializers.DictField()
    
class QuickScanRequestSerializer(serializers.Serializer):
    """Serializer for quick scan requests"""
    target = serializers.CharField(max_length=255)
    scan_type = serializers.ChoiceField(choices=NetworkTarget.SCAN_TYPES)
    ports = serializers.CharField(max_length=255, default="1-1000")
    name = serializers.CharField(max_length=255, required=False)