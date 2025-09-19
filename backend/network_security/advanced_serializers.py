from rest_framework import serializers
from .models import (
    NetworkTopology, NetworkNode, NetworkConnection, 
    IntrusionDetectionRule, TrafficPattern
)

class NetworkNodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkNode
        fields = [
            'id', 'ip_address', 'hostname', 'mac_address', 'node_type',
            'os_fingerprint', 'position_x', 'position_y', 'is_gateway',
            'last_seen', 'metadata'
        ]

class NetworkConnectionSerializer(serializers.ModelSerializer):
    source_ip = serializers.CharField(source='source_node.ip_address', read_only=True)
    destination_ip = serializers.CharField(source='destination_node.ip_address', read_only=True)
    
    class Meta:
        model = NetworkConnection
        fields = [
            'id', 'source_ip', 'destination_ip', 'connection_type',
            'latency', 'bandwidth', 'last_seen', 'metadata'
        ]

class NetworkTopologySerializer(serializers.ModelSerializer):
    nodes = NetworkNodeSerializer(many=True, read_only=True)
    connections = NetworkConnectionSerializer(many=True, read_only=True)
    node_count = serializers.SerializerMethodField()
    
    class Meta:
        model = NetworkTopology
        fields = [
            'id', 'name', 'description', 'network_range', 'discovered_at',
            'updated_at', 'topology_data', 'nodes', 'connections', 'node_count'
        ]
        read_only_fields = ['created_by']
    
    def get_node_count(self, obj):
        return obj.nodes.count()

class IntrusionDetectionRuleSerializer(serializers.ModelSerializer):
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    
    class Meta:
        model = IntrusionDetectionRule
        fields = [
            'id', 'name', 'description', 'rule_type', 'severity', 'pattern',
            'action', 'is_active', 'created_at', 'updated_at', 'created_by_username'
        ]
        read_only_fields = ['created_by']

class TrafficPatternSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrafficPattern
        fields = [
            'id', 'pattern_type', 'source_ip', 'destination_ip', 'source_port',
            'destination_port', 'protocol', 'packet_count', 'byte_count',
            'duration', 'detected_at', 'confidence_score', 'metadata'
        ]

class TopologyDiscoveryRequestSerializer(serializers.Serializer):
    """Serializer for topology discovery requests"""
    name = serializers.CharField(max_length=255)
    network_range = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=500, required=False)
    discovery_methods = serializers.ListField(
        child=serializers.CharField(),
        default=['ping_sweep', 'arp_scan']
    )