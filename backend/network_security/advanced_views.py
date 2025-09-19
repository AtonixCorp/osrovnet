from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
import threading

from .models import (
    NetworkTopology, NetworkNode, NetworkConnection,
    IntrusionDetectionRule, TrafficPattern
)
from .advanced_serializers import (
    NetworkTopologySerializer, NetworkNodeSerializer, NetworkConnectionSerializer,
    IntrusionDetectionRuleSerializer, TrafficPatternSerializer,
    TopologyDiscoveryRequestSerializer
)
from .topology_service import topology_mapper
from .ids_service import intrusion_detector

class NetworkTopologyViewSet(viewsets.ModelViewSet):
    """ViewSet for network topology management"""
    queryset = NetworkTopology.objects.all()
    serializer_class = NetworkTopologySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
    
    def get_queryset(self):
        queryset = NetworkTopology.objects.all()
        network_range = self.request.query_params.get('network_range', None)
        
        if network_range:
            queryset = queryset.filter(network_range__icontains=network_range)
            
        return queryset.order_by('-updated_at')
    
    @action(detail=False, methods=['post'])
    def discover(self, request):
        """Start topology discovery for a network range"""
        serializer = TopologyDiscoveryRequestSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data
            
            try:
                # Start topology discovery in background
                def start_discovery():
                    topology_mapper.discover_topology(
                        network_range=data['network_range'],
                        topology_name=data['name'],
                        user=request.user,
                        methods=data.get('discovery_methods', ['ping_sweep', 'arp_scan'])
                    )
                
                thread = threading.Thread(target=start_discovery)
                thread.daemon = True
                thread.start()
                
                return Response({
                    'message': 'Topology discovery started',
                    'network_range': data['network_range'],
                    'name': data['name']
                }, status=status.HTTP_202_ACCEPTED)
                
            except Exception as e:
                return Response({
                    'error': f'Failed to start topology discovery: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['get'])
    def visualization_data(self, request, pk=None):
        """Get topology data formatted for visualization"""
        try:
            topology = self.get_object()
            vis_data = topology_mapper.get_topology_visualization_data(topology.id)
            return Response(vis_data)
        except Exception as e:
            return Response({
                'error': f'Failed to get visualization data: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class NetworkNodeViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for network nodes"""
    queryset = NetworkNode.objects.all()
    serializer_class = NetworkNodeSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = NetworkNode.objects.all()
        topology_id = self.request.query_params.get('topology_id', None)
        node_type = self.request.query_params.get('node_type', None)
        is_gateway = self.request.query_params.get('is_gateway', None)
        
        if topology_id:
            queryset = queryset.filter(topology_id=topology_id)
        if node_type:
            queryset = queryset.filter(node_type=node_type)
        if is_gateway is not None:
            queryset = queryset.filter(is_gateway=is_gateway.lower() == 'true')
            
        return queryset.order_by('-last_seen')

class IntrusionDetectionRuleViewSet(viewsets.ModelViewSet):
    """ViewSet for IDS rules management"""
    queryset = IntrusionDetectionRule.objects.all()
    serializer_class = IntrusionDetectionRuleSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
    
    def get_queryset(self):
        queryset = IntrusionDetectionRule.objects.all()
        rule_type = self.request.query_params.get('rule_type', None)
        severity = self.request.query_params.get('severity', None)
        is_active = self.request.query_params.get('is_active', None)
        
        if rule_type:
            queryset = queryset.filter(rule_type=rule_type)
        if severity:
            queryset = queryset.filter(severity=severity)
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
            
        return queryset.order_by('-created_at')
    
    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        """Toggle rule active status"""
        rule = self.get_object()
        rule.is_active = not rule.is_active
        rule.save()
        
        serializer = IntrusionDetectionRuleSerializer(rule)
        return Response(serializer.data)

class TrafficPatternViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for traffic patterns"""
    queryset = TrafficPattern.objects.all()
    serializer_class = TrafficPatternSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = TrafficPattern.objects.all()
        pattern_type = self.request.query_params.get('pattern_type', None)
        source_ip = self.request.query_params.get('source_ip', None)
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
            
        queryset = queryset.filter(detected_at__gte=time_filter)
        
        if pattern_type:
            queryset = queryset.filter(pattern_type=pattern_type)
        if source_ip:
            queryset = queryset.filter(source_ip=source_ip)
            
        return queryset.order_by('-detected_at')

class IntrusionDetectionDashboardView(APIView):
    """API view for IDS dashboard data"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get IDS dashboard statistics"""
        try:
            stats = intrusion_detector.get_detection_statistics()
            
            # Add additional metrics
            stats['rules_active'] = IntrusionDetectionRule.objects.filter(is_active=True).count()
            stats['rules_total'] = IntrusionDetectionRule.objects.count()
            
            # Recent patterns
            recent_patterns = TrafficPattern.objects.filter(
                detected_at__gte=timezone.now() - timedelta(hours=24)
            ).values('pattern_type').annotate(count=Count('id')).order_by('-count')
            
            stats['recent_patterns'] = list(recent_patterns)
            
            return Response(stats)
            
        except Exception as e:
            return Response({
                'error': f'Failed to get IDS statistics: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class IDSControlView(APIView):
    """API view for IDS control operations"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Control IDS operations"""
        action = request.data.get('action')
        
        if action == 'start':
            try:
                intrusion_detector.start_monitoring()
                return Response({'message': 'IDS monitoring started'})
            except Exception as e:
                return Response({
                    'error': f'Failed to start IDS: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        elif action == 'stop':
            try:
                intrusion_detector.stop_monitoring()
                return Response({'message': 'IDS monitoring stopped'})
            except Exception as e:
                return Response({
                    'error': f'Failed to stop IDS: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        elif action == 'status':
            return Response({
                'running': intrusion_detector.running,
                'buffer_size': len(intrusion_detector.traffic_buffer)
            })
        
        else:
            return Response({
                'error': 'Invalid action. Use: start, stop, or status'
            }, status=status.HTTP_400_BAD_REQUEST)

class AdvancedScanView(APIView):
    """API view for advanced scanning operations"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Start advanced scan with custom parameters"""
        target = request.data.get('target')
        scan_type = request.data.get('scan_type', 'tcp_syn')
        ports = request.data.get('ports', '1-1000')
        enable_os_detection = request.data.get('enable_os_detection', False)
        enable_service_detection = request.data.get('enable_service_detection', True)
        enable_vulnerability_scan = request.data.get('enable_vulnerability_scan', True)
        
        if not target:
            return Response({
                'error': 'Target is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            from .services import get_network_scanner
            scanner = get_network_scanner()
            
            # Perform advanced scan
            results = scanner.scan_target(
                target=target,
                scan_type=scan_type,
                ports=ports,
                enable_os_detection=enable_os_detection,
                enable_service_detection=enable_service_detection,
                enable_vulnerability_scan=enable_vulnerability_scan
            )
            
            return Response({
                'message': 'Advanced scan completed',
                'results': results
            })
            
        except Exception as e:
            return Response({
                'error': f'Advanced scan failed: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class NetworkAnalyticsView(APIView):
    """API view for network analytics"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get network analytics data"""
        try:
            # Topology analytics
            topology_stats = {
                'total_topologies': NetworkTopology.objects.count(),
                'total_nodes': NetworkNode.objects.count(),
                'total_connections': NetworkConnection.objects.count(),
                'node_types': list(NetworkNode.objects.values('node_type').annotate(
                    count=Count('id')
                ).order_by('-count'))
            }
            
            # Traffic pattern analytics
            pattern_stats = {
                'total_patterns': TrafficPattern.objects.count(),
                'patterns_24h': TrafficPattern.objects.filter(
                    detected_at__gte=timezone.now() - timedelta(hours=24)
                ).count(),
                'pattern_types': list(TrafficPattern.objects.values('pattern_type').annotate(
                    count=Count('id')
                ).order_by('-count'))
            }
            
            # IDS analytics
            ids_stats = intrusion_detector.get_detection_statistics()
            
            return Response({
                'topology': topology_stats,
                'patterns': pattern_stats,
                'ids': ids_stats
            })
            
        except Exception as e:
            return Response({
                'error': f'Failed to get analytics: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)