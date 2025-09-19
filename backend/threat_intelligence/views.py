"""
Threat Intelligence Views
"""
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
import threading

from .models import (
    ThreatFeed, IndicatorOfCompromise, ThreatActor, ThreatCampaign,
    ThreatIntelligenceReport, ThreatHunt, ThreatMatch,
    ThreatResponsePlaybook, ThreatResponseExecution
)
from .serializers import (
    ThreatFeedSerializer, IndicatorOfCompromiseSerializer, ThreatActorSerializer,
    ThreatCampaignSerializer, ThreatIntelligenceReportSerializer, ThreatHuntSerializer,
    ThreatMatchSerializer, ThreatResponsePlaybookSerializer, ThreatResponseExecutionSerializer,
    BulkIOCImportSerializer, IOCSearchSerializer, IOCExtractionSerializer, IOCMatchCheckSerializer
)
from .ioc_service import ioc_manager

class ThreatFeedViewSet(viewsets.ModelViewSet):
    """ViewSet for threat feed management"""
    queryset = ThreatFeed.objects.all()
    serializer_class = ThreatFeedSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
    
    def get_queryset(self):
        queryset = ThreatFeed.objects.all()
        feed_type = self.request.query_params.get('feed_type', None)
        status_filter = self.request.query_params.get('status', None)
        is_enabled = self.request.query_params.get('is_enabled', None)
        
        if feed_type:
            queryset = queryset.filter(feed_type=feed_type)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if is_enabled is not None:
            queryset = queryset.filter(is_enabled=is_enabled.lower() == 'true')
            
        return queryset.order_by('-created_at')
    
    @action(detail=True, methods=['post'])
    def sync_feed(self, request, pk=None):
        """Sync threat feed with external source"""
        feed = self.get_object()
        
        try:
            # Start feed sync in background
            def sync_feed_data():
                # Placeholder for actual feed sync implementation
                # In production, this would connect to external APIs
                pass
            
            thread = threading.Thread(target=sync_feed_data)
            thread.daemon = True
            thread.start()
            
            return Response({
                'message': f'Syncing feed {feed.name}',
                'feed_id': feed.id
            }, status=status.HTTP_202_ACCEPTED)
            
        except Exception as e:
            return Response({
                'error': f'Failed to sync feed: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class IndicatorOfCompromiseViewSet(viewsets.ModelViewSet):
    """ViewSet for IOC management"""
    queryset = IndicatorOfCompromise.objects.all()
    serializer_class = IndicatorOfCompromiseSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
    
    def get_queryset(self):
        queryset = IndicatorOfCompromise.objects.select_related('source_feed', 'created_by')
        
        ioc_type = self.request.query_params.get('ioc_type', None)
        threat_type = self.request.query_params.get('threat_type', None)
        severity = self.request.query_params.get('severity', None)
        status_filter = self.request.query_params.get('status', None)
        source_feed = self.request.query_params.get('source_feed', None)
        search = self.request.query_params.get('search', None)
        
        if ioc_type:
            queryset = queryset.filter(ioc_type=ioc_type)
        if threat_type:
            queryset = queryset.filter(threat_type=threat_type)
        if severity:
            queryset = queryset.filter(severity=severity)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if source_feed:
            queryset = queryset.filter(source_feed_id=source_feed)
        if search:
            queryset = queryset.filter(
                Q(value__icontains=search) |
                Q(description__icontains=search)
                # Remove tags search for SQLite compatibility
                # Q(tags__contains=[search])
            )
            
        return queryset.order_by('-first_seen')
    
    @action(detail=False, methods=['post'])
    def bulk_import(self, request):
        """Bulk import IOCs"""
        serializer = BulkIOCImportSerializer(data=request.data)
        if serializer.is_valid():
            try:
                source_feed = ThreatFeed.objects.get(id=serializer.validated_data['source_feed_id'])
                results = ioc_manager.bulk_import_iocs(
                    serializer.validated_data['iocs_data'],
                    source_feed,
                    request.user
                )
                return Response(results, status=status.HTTP_200_OK)
            except ThreatFeed.DoesNotExist:
                return Response({'error': 'Source feed not found'}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'])
    def search(self, request):
        """Advanced IOC search"""
        serializer = IOCSearchSerializer(data=request.data)
        if serializer.is_valid():
            filters = {k: v for k, v in serializer.validated_data.items() if v is not None}
            query = filters.pop('query', '')
            
            iocs = ioc_manager.search_iocs(query, filters)
            
            # Paginate results
            page = self.paginate_queryset(iocs)
            if page is not None:
                ioc_serializer = IndicatorOfCompromiseSerializer(page, many=True)
                return self.get_paginated_response(ioc_serializer.data)
            
            ioc_serializer = IndicatorOfCompromiseSerializer(iocs, many=True)
            return Response(ioc_serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'])
    def extract_from_text(self, request):
        """Extract IOCs from text"""
        serializer = IOCExtractionSerializer(data=request.data)
        if serializer.is_valid():
            text = serializer.validated_data['text']
            create_iocs = serializer.validated_data.get('create_iocs', False)
            source_feed_id = serializer.validated_data.get('source_feed_id')
            
            extracted_iocs = ioc_manager.extract_iocs_from_text(text)
            
            if create_iocs and source_feed_id:
                try:
                    source_feed = ThreatFeed.objects.get(id=source_feed_id)
                    created_iocs = []
                    
                    for ioc_type, values in extracted_iocs.items():
                        for value in values:
                            ioc_data = {
                                'value': value,
                                'ioc_type': ioc_type,
                                'threat_type': 'suspicious',
                                'severity': 'medium'
                            }
                            ioc = ioc_manager.create_ioc(ioc_data, source_feed, request.user)
                            created_iocs.append(IndicatorOfCompromiseSerializer(ioc).data)
                    
                    return Response({
                        'extracted_iocs': extracted_iocs,
                        'created_iocs': created_iocs
                    })
                except ThreatFeed.DoesNotExist:
                    return Response({'error': 'Source feed not found'}, status=status.HTTP_404_NOT_FOUND)
            
            return Response({'extracted_iocs': extracted_iocs})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['post'])
    def enrich(self, request, pk=None):
        """Enrich IOC with external sources"""
        ioc = self.get_object()
        
        try:
            enrichment_data = ioc_manager.enrich_ioc_context(ioc)
            return Response({
                'ioc_id': ioc.id,
                'enrichment_data': enrichment_data
            })
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ThreatMatchViewSet(viewsets.ModelViewSet):
    """ViewSet for threat matches"""
    queryset = ThreatMatch.objects.all()
    serializer_class = ThreatMatchSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = ThreatMatch.objects.select_related('ioc', 'analyst')
        
        status_filter = self.request.query_params.get('status', None)
        source_ip = self.request.query_params.get('source_ip', None)
        ioc_type = self.request.query_params.get('ioc_type', None)
        time_range = self.request.query_params.get('time_range', '24h')
        
        # Apply time range filter
        now = timezone.now()
        if time_range == '1h':
            time_filter = now - timedelta(hours=1)
        elif time_range == '24h':
            time_filter = now - timedelta(hours=24)
        elif time_range == '7d':
            time_filter = now - timedelta(days=7)
        else:
            time_filter = now - timedelta(hours=24)
        
        queryset = queryset.filter(first_seen__gte=time_filter)
        
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if source_ip:
            queryset = queryset.filter(source_ip=source_ip)
        if ioc_type:
            queryset = queryset.filter(ioc__ioc_type=ioc_type)
        
        return queryset.order_by('-first_seen')
    
    @action(detail=False, methods=['post'])
    def check_matches(self, request):
        """Check for IOC matches"""
        serializer = IOCMatchCheckSerializer(data=request.data)
        if serializer.is_valid():
            value = serializer.validated_data['value']
            ioc_type = serializer.validated_data.get('ioc_type')
            
            matches = ioc_manager.check_ioc_matches(value, ioc_type)
            match_serializer = ThreatMatchSerializer(matches, many=True)
            
            return Response({
                'matches_found': len(matches),
                'matches': match_serializer.data
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['post'])
    def assign_to_me(self, request, pk=None):
        """Assign threat match to current user"""
        match = self.get_object()
        match.analyst = request.user
        match.save()
        
        serializer = ThreatMatchSerializer(match)
        return Response(serializer.data)

class ThreatActorViewSet(viewsets.ModelViewSet):
    """ViewSet for threat actors"""
    queryset = ThreatActor.objects.all()
    serializer_class = ThreatActorSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = ThreatActor.objects.all()
        actor_type = self.request.query_params.get('actor_type', None)
        is_active = self.request.query_params.get('is_active', None)
        country = self.request.query_params.get('country', None)
        
        if actor_type:
            queryset = queryset.filter(actor_type=actor_type)
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        if country:
            queryset = queryset.filter(country__icontains=country)
        
        return queryset.order_by('-last_activity')

class ThreatHuntViewSet(viewsets.ModelViewSet):
    """ViewSet for threat hunting"""
    queryset = ThreatHunt.objects.all()
    serializer_class = ThreatHuntSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def perform_create(self, serializer):
        serializer.save(hunter=self.request.user)
    
    def get_queryset(self):
        queryset = ThreatHunt.objects.select_related('hunter')
        
        status_filter = self.request.query_params.get('status', None)
        hunter = self.request.query_params.get('hunter', None)
        hunt_type = self.request.query_params.get('hunt_type', None)
        
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if hunter:
            queryset = queryset.filter(hunter_id=hunter)
        if hunt_type:
            queryset = queryset.filter(hunt_type=hunt_type)
        
        return queryset.order_by('-start_date')
    
    @action(detail=True, methods=['post'])
    def start_hunt(self, request, pk=None):
        """Start a threat hunt"""
        hunt = self.get_object()
        
        if hunt.status != 'planning':
            return Response({
                'error': 'Hunt must be in planning status to start'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        hunt.status = 'active'
        hunt.start_date = timezone.now()
        hunt.save()
        
        serializer = ThreatHuntSerializer(hunt)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def complete_hunt(self, request, pk=None):
        """Complete a threat hunt"""
        hunt = self.get_object()
        
        hunt.status = 'completed'
        hunt.end_date = timezone.now()
        hunt.findings = request.data.get('findings', hunt.findings)
        hunt.save()
        
        serializer = ThreatHuntSerializer(hunt)
        return Response(serializer.data)

class ThreatIntelligenceDashboardView(APIView):
    """Dashboard view for threat intelligence overview"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get threat intelligence dashboard data"""
        try:
            # IOC statistics
            ioc_stats = ioc_manager.get_ioc_statistics()
            
            # Recent matches
            recent_matches = ThreatMatch.objects.filter(
                first_seen__gte=timezone.now() - timedelta(hours=24)
            ).count()
            
            # Threat actors
            total_actors = ThreatActor.objects.count()
            active_actors = ThreatActor.objects.filter(is_active=True).count()
            
            # Threat feeds
            total_feeds = ThreatFeed.objects.count()
            active_feeds = ThreatFeed.objects.filter(is_enabled=True, status='active').count()
            
            # Recent hunts
            active_hunts = ThreatHunt.objects.filter(status='active').count()
            completed_hunts = ThreatHunt.objects.filter(
                status='completed',
                end_date__gte=timezone.now() - timedelta(days=7)
            ).count()
            
            # Top threats by severity
            threat_breakdown = IndicatorOfCompromise.objects.filter(
                status='active'
            ).values('severity').annotate(count=Count('id')).order_by('-count')
            
            # Top IOC types
            ioc_type_breakdown = IndicatorOfCompromise.objects.filter(
                status='active'
            ).values('ioc_type').annotate(count=Count('id')).order_by('-count')
            
            dashboard_data = {
                'ioc_statistics': ioc_stats,
                'recent_matches': recent_matches,
                'threat_actors': {
                    'total': total_actors,
                    'active': active_actors
                },
                'threat_feeds': {
                    'total': total_feeds,
                    'active': active_feeds
                },
                'threat_hunts': {
                    'active': active_hunts,
                    'completed_this_week': completed_hunts
                },
                'threat_breakdown': list(threat_breakdown),
                'ioc_type_breakdown': list(ioc_type_breakdown)
            }
            
            return Response(dashboard_data)
            
        except Exception as e:
            return Response({
                'error': f'Failed to get dashboard data: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class IOCManagementView(APIView):
    """IOC management utilities"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """IOC management operations"""
        action = request.data.get('action')
        
        if action == 'expire_old':
            days = request.data.get('days', 90)
            try:
                expired_count = ioc_manager.expire_old_iocs(days)
                return Response({
                    'message': f'Expired {expired_count} old IOCs'
                })
            except Exception as e:
                return Response({
                    'error': f'Failed to expire IOCs: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        elif action == 'cleanup_expired':
            try:
                deleted_count = IndicatorOfCompromise.objects.filter(
                    status='expired',
                    expires_at__lt=timezone.now()
                ).delete()[0]
                
                return Response({
                    'message': f'Cleaned up {deleted_count} expired IOCs'
                })
            except Exception as e:
                return Response({
                    'error': f'Failed to cleanup IOCs: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        else:
            return Response({
                'error': 'Invalid action. Use: expire_old, cleanup_expired'
            }, status=status.HTTP_400_BAD_REQUEST)
