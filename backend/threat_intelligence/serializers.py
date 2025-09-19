"""
Threat Intelligence Serializers
"""
from rest_framework import serializers
from .models import (
    ThreatFeed, IndicatorOfCompromise, ThreatActor, ThreatCampaign,
    ThreatIntelligenceReport, ThreatHunt, ThreatMatch, 
    ThreatResponsePlaybook, ThreatResponseExecution
)

class ThreatFeedSerializer(serializers.ModelSerializer):
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    ioc_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ThreatFeed
        fields = [
            'id', 'name', 'feed_type', 'url', 'description', 'status',
            'last_updated', 'update_interval', 'is_enabled', 'confidence_level',
            'created_at', 'updated_at', 'created_by_username', 'ioc_count', 'metadata'
        ]
        read_only_fields = ['created_by']
    
    def get_ioc_count(self, obj):
        return obj.iocs.filter(status='active').count()

class IndicatorOfCompromiseSerializer(serializers.ModelSerializer):
    source_feed_name = serializers.CharField(source='source_feed.name', read_only=True)
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    matches_count = serializers.SerializerMethodField()
    
    class Meta:
        model = IndicatorOfCompromise
        fields = [
            'id', 'value', 'ioc_type', 'threat_type', 'severity', 'status',
            'confidence', 'source_feed', 'source_feed_name', 'first_seen', 
            'last_seen', 'expires_at', 'tags', 'description', 'context',
            'tlp', 'created_by_username', 'matches_count'
        ]
        read_only_fields = ['created_by', 'first_seen']
    
    def get_matches_count(self, obj):
        return obj.threatmatch_set.count()

class ThreatActorSerializer(serializers.ModelSerializer):
    campaigns_count = serializers.SerializerMethodField()
    reports_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ThreatActor
        fields = [
            'id', 'name', 'aliases', 'actor_type', 'description', 'country',
            'motivation', 'capabilities', 'targets', 'ttps', 'first_seen',
            'last_activity', 'is_active', 'confidence', 'metadata',
            'campaigns_count', 'reports_count'
        ]
    
    def get_campaigns_count(self, obj):
        return obj.threatcampaign_set.count()
    
    def get_reports_count(self, obj):
        return obj.reports.count()

class ThreatCampaignSerializer(serializers.ModelSerializer):
    threat_actor_name = serializers.CharField(source='threat_actor.name', read_only=True)
    iocs_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ThreatCampaign
        fields = [
            'id', 'name', 'description', 'threat_actor', 'threat_actor_name',
            'status', 'first_seen', 'last_seen', 'targets', 'attack_patterns',
            'malware_families', 'confidence', 'metadata', 'iocs_count'
        ]
    
    def get_iocs_count(self, obj):
        return obj.iocs.count()

class ThreatMatchSerializer(serializers.ModelSerializer):
    ioc_value = serializers.CharField(source='ioc.value', read_only=True)
    ioc_type = serializers.CharField(source='ioc.ioc_type', read_only=True)
    ioc_severity = serializers.CharField(source='ioc.severity', read_only=True)
    analyst_username = serializers.CharField(source='analyst.username', read_only=True)
    
    class Meta:
        model = ThreatMatch
        fields = [
            'id', 'ioc', 'ioc_value', 'ioc_type', 'ioc_severity', 'match_type',
            'matched_value', 'source_ip', 'destination_ip', 'source_event',
            'event_data', 'confidence', 'status', 'first_seen', 'last_seen',
            'count', 'analyst', 'analyst_username', 'notes'
        ]

class ThreatHuntSerializer(serializers.ModelSerializer):
    hunter_username = serializers.CharField(source='hunter.username', read_only=True)
    iocs_discovered_count = serializers.SerializerMethodField()
    duration = serializers.SerializerMethodField()
    
    class Meta:
        model = ThreatHunt
        fields = [
            'id', 'name', 'description', 'hypothesis', 'hunt_type', 'status',
            'hunter', 'hunter_username', 'start_date', 'end_date', 'data_sources',
            'search_queries', 'findings', 'confidence', 'metadata',
            'iocs_discovered_count', 'duration'
        ]
        read_only_fields = ['hunter']
    
    def get_iocs_discovered_count(self, obj):
        return obj.iocs_discovered.count()
    
    def get_duration(self, obj):
        if obj.end_date and obj.start_date:
            delta = obj.end_date - obj.start_date
            return delta.total_seconds() / 3600  # hours
        return None

class ThreatIntelligenceReportSerializer(serializers.ModelSerializer):
    author_username = serializers.CharField(source='author.username', read_only=True)
    iocs_count = serializers.SerializerMethodField()
    threat_actors_count = serializers.SerializerMethodField()
    campaigns_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ThreatIntelligenceReport
        fields = [
            'id', 'title', 'report_type', 'content', 'summary', 'author',
            'author_username', 'source', 'confidence', 'severity', 'tlp',
            'tags', 'published_at', 'updated_at', 'metadata',
            'iocs_count', 'threat_actors_count', 'campaigns_count'
        ]
        read_only_fields = ['author', 'published_at']
    
    def get_iocs_count(self, obj):
        return obj.iocs.count()
    
    def get_threat_actors_count(self, obj):
        return obj.threat_actors.count()
    
    def get_campaigns_count(self, obj):
        return obj.campaigns.count()

class ThreatResponsePlaybookSerializer(serializers.ModelSerializer):
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    executions_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ThreatResponsePlaybook
        fields = [
            'id', 'name', 'description', 'trigger_type', 'trigger_conditions',
            'actions', 'is_active', 'auto_execute', 'execution_count',
            'last_executed', 'created_by_username', 'created_at', 'updated_at',
            'executions_count'
        ]
        read_only_fields = ['created_by', 'execution_count', 'last_executed']
    
    def get_executions_count(self, obj):
        return obj.threatresponseexecution_set.count()

class ThreatResponseExecutionSerializer(serializers.ModelSerializer):
    playbook_name = serializers.CharField(source='playbook.name', read_only=True)
    executed_by_username = serializers.CharField(source='executed_by.username', read_only=True)
    duration = serializers.SerializerMethodField()
    
    class Meta:
        model = ThreatResponseExecution
        fields = [
            'id', 'playbook', 'playbook_name', 'trigger_event', 'status',
            'started_at', 'completed_at', 'executed_actions', 'results',
            'errors', 'executed_by_username', 'duration'
        ]
    
    def get_duration(self, obj):
        if obj.completed_at and obj.started_at:
            delta = obj.completed_at - obj.started_at
            return delta.total_seconds()
        return None

# Request serializers for bulk operations
class BulkIOCImportSerializer(serializers.Serializer):
    """Serializer for bulk IOC import"""
    source_feed_id = serializers.IntegerField()
    iocs_data = serializers.ListField(
        child=serializers.DictField(),
        min_length=1
    )
    
class IOCSearchSerializer(serializers.Serializer):
    """Serializer for IOC search requests"""
    query = serializers.CharField(required=False, allow_blank=True)
    ioc_type = serializers.ChoiceField(
        choices=IndicatorOfCompromise.IOC_TYPES,
        required=False
    )
    threat_type = serializers.ChoiceField(
        choices=IndicatorOfCompromise.THREAT_TYPES,
        required=False
    )
    severity = serializers.ChoiceField(
        choices=IndicatorOfCompromise.SEVERITY_LEVELS,
        required=False
    )
    source_feed = serializers.IntegerField(required=False)
    date_from = serializers.DateTimeField(required=False)
    status = serializers.ChoiceField(
        choices=IndicatorOfCompromise.STATUS_CHOICES,
        required=False
    )

class IOCExtractionSerializer(serializers.Serializer):
    """Serializer for IOC extraction from text"""
    text = serializers.CharField()
    create_iocs = serializers.BooleanField(default=False)
    source_feed_id = serializers.IntegerField(required=False)

class IOCMatchCheckSerializer(serializers.Serializer):
    """Serializer for checking IOC matches"""
    value = serializers.CharField()
    ioc_type = serializers.ChoiceField(
        choices=IndicatorOfCompromise.IOC_TYPES,
        required=False
    )
    source_ip = serializers.IPAddressField(required=False)
    destination_ip = serializers.IPAddressField(required=False)
    source_event = serializers.CharField(required=False)