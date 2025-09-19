from django.shortcuts import render
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
import threading
import json

from .models import (
    NetworkTarget, NetworkScan, DiscoveredHost, DiscoveredPort, 
    Vulnerability, NetworkTraffic, NetworkAlert
)
from .serializers import (
    NetworkTargetSerializer, NetworkScanSerializer, DiscoveredHostSerializer,
    DiscoveredPortSerializer, VulnerabilitySerializer, NetworkTrafficSerializer,
    NetworkAlertSerializer, ScanStatisticsSerializer, NetworkOverviewSerializer,
    QuickScanRequestSerializer
)
from .services import NetworkScanningService

class NetworkTargetViewSet(viewsets.ModelViewSet):
    """ViewSet for managing network scan targets"""
    queryset = NetworkTarget.objects.all()
    serializer_class = NetworkTargetSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
    
    def get_queryset(self):
        queryset = NetworkTarget.objects.all()
        is_active = self.request.query_params.get('is_active', None)
        scan_type = self.request.query_params.get('scan_type', None)
        
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        if scan_type:
            queryset = queryset.filter(scan_type=scan_type)
            
        return queryset.order_by('-created_at')
    
    @action(detail=True, methods=['post'])
    def start_scan(self, request, pk=None):
        """Start a scan for this target"""
        target = self.get_object()
        
        # Check if there's already a running scan for this target
        existing_scan = NetworkScan.objects.filter(
            target=target, 
            status='running'
        ).first()
        
        if existing_scan:
            return Response(
                {'error': 'A scan is already running for this target'}, 
                status=status.HTTP_409_CONFLICT
            )
        
        # Create new scan
        scan = NetworkScan.objects.create(
            target=target,
            initiated_by=request.user,
            status='running',
            started_at=timezone.now()
        )
        
        # Start scan in background thread
        def run_scan():
            service = NetworkScanningService()
            service.start_scan(scan.id)
        
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        serializer = NetworkScanSerializer(scan)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class NetworkScanViewSet(viewsets.ModelViewSet):
    """ViewSet for managing network scans"""
    queryset = NetworkScan.objects.all()
    serializer_class = NetworkScanSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = NetworkScan.objects.select_related('target', 'initiated_by').prefetch_related('hosts__ports__vulnerabilities')
        
        status_filter = self.request.query_params.get('status', None)
        target_id = self.request.query_params.get('target_id', None)
        date_from = self.request.query_params.get('date_from', None)
        
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if target_id:
            queryset = queryset.filter(target_id=target_id)
        if date_from:
            queryset = queryset.filter(started_at__gte=date_from)
            
        return queryset.order_by('-started_at')
    
    @action(detail=True, methods=['post'])
    def stop_scan(self, request, pk=None):
        """Stop a running scan"""
        scan = self.get_object()
        
        if scan.status != 'running':
            return Response(
                {'error': 'Scan is not running'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        scan.status = 'cancelled'
        scan.completed_at = timezone.now()
        scan.duration = scan.completed_at - scan.started_at
        scan.save()
        
        serializer = NetworkScanSerializer(scan)
        return Response(serializer.data)

class DiscoveredHostViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for discovered hosts"""
    queryset = DiscoveredHost.objects.all()
    serializer_class = DiscoveredHostSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = DiscoveredHost.objects.prefetch_related('ports__vulnerabilities')
        
        scan_id = self.request.query_params.get('scan_id', None)
        state = self.request.query_params.get('state', None)
        has_vulnerabilities = self.request.query_params.get('has_vulnerabilities', None)
        
        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)
        if state:
            queryset = queryset.filter(state=state)
        if has_vulnerabilities is not None:
            if has_vulnerabilities.lower() == 'true':
                queryset = queryset.filter(ports__vulnerabilities__isnull=False).distinct()
            else:
                queryset = queryset.filter(ports__vulnerabilities__isnull=True).distinct()
                
        return queryset.order_by('-last_seen')

class VulnerabilityViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for vulnerabilities"""
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = Vulnerability.objects.select_related('port__host')
        
        severity = self.request.query_params.get('severity', None)
        scan_id = self.request.query_params.get('scan_id', None)
        host_id = self.request.query_params.get('host_id', None)
        
        if severity:
            queryset = queryset.filter(severity=severity)
        if scan_id:
            queryset = queryset.filter(port__host__scan_id=scan_id)
        if host_id:
            queryset = queryset.filter(port__host_id=host_id)
            
        return queryset.order_by('-cvss_score', '-discovered_at')

class NetworkTrafficViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for network traffic monitoring"""
    queryset = NetworkTraffic.objects.all()
    serializer_class = NetworkTrafficSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = NetworkTraffic.objects.all()
        
        protocol = self.request.query_params.get('protocol', None)
        source_ip = self.request.query_params.get('source_ip', None)
        destination_ip = self.request.query_params.get('destination_ip', None)
        time_range = self.request.query_params.get('time_range', '1h')  # 1h, 24h, 7d
        
        # Apply time range filter
        now = timezone.now()
        if time_range == '1h':
            time_filter = now - timedelta(hours=1)
        elif time_range == '24h':
            time_filter = now - timedelta(hours=24)
        elif time_range == '7d':
            time_filter = now - timedelta(days=7)
        else:
            time_filter = now - timedelta(hours=1)
            
        queryset = queryset.filter(timestamp__gte=time_filter)
        
        if protocol:
            queryset = queryset.filter(protocol=protocol)
        if source_ip:
            queryset = queryset.filter(source_ip=source_ip)
        if destination_ip:
            queryset = queryset.filter(destination_ip=destination_ip)
            
        return queryset.order_by('-timestamp')

class NetworkAlertViewSet(viewsets.ModelViewSet):
    """ViewSet for network alerts"""
    queryset = NetworkAlert.objects.all()
    serializer_class = NetworkAlertSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = NetworkAlert.objects.select_related('assigned_to', 'related_scan')
        
        status_filter = self.request.query_params.get('status', None)
        severity = self.request.query_params.get('severity', None)
        alert_type = self.request.query_params.get('alert_type', None)
        assigned_to_me = self.request.query_params.get('assigned_to_me', None)
        
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if severity:
            queryset = queryset.filter(severity=severity)
        if alert_type:
            queryset = queryset.filter(alert_type=alert_type)
        if assigned_to_me and assigned_to_me.lower() == 'true':
            queryset = queryset.filter(assigned_to=self.request.user)
            
        return queryset.order_by('-created_at')
    
    @action(detail=True, methods=['post'])
    def assign_to_me(self, request, pk=None):
        """Assign alert to current user"""
        alert = self.get_object()
        alert.assigned_to = request.user
        alert.save()
        
        serializer = NetworkAlertSerializer(alert)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def mark_resolved(self, request, pk=None):
        """Mark alert as resolved"""
        alert = self.get_object()
        alert.status = 'resolved'
        alert.updated_at = timezone.now()
        alert.save()
        
        serializer = NetworkAlertSerializer(alert)
        return Response(serializer.data)

class DashboardStatisticsView(APIView):
    """API view for dashboard statistics"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        # Scan statistics
        total_scans = NetworkScan.objects.count()
        completed_scans = NetworkScan.objects.filter(status='completed').count()
        failed_scans = NetworkScan.objects.filter(status='failed').count()
        running_scans = NetworkScan.objects.filter(status='running').count()
        
        # Host and vulnerability statistics
        total_hosts = DiscoveredHost.objects.count()
        total_ports = DiscoveredPort.objects.count()
        total_vulnerabilities = Vulnerability.objects.count()
        critical_vulnerabilities = Vulnerability.objects.filter(severity='critical').count()
        high_vulnerabilities = Vulnerability.objects.filter(severity='high').count()
        
        # Recent alerts
        recent_alerts = NetworkAlert.objects.filter(
            created_at__gte=timezone.now() - timedelta(hours=24),
            status='open'
        ).count()
        
        statistics = {
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'failed_scans': failed_scans,
            'running_scans': running_scans,
            'total_hosts': total_hosts,
            'total_ports': total_ports,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_vulnerabilities': critical_vulnerabilities,
            'high_vulnerabilities': high_vulnerabilities,
            'recent_alerts': recent_alerts,
        }
        
        serializer = ScanStatisticsSerializer(statistics)
        return Response(serializer.data)

class NetworkOverviewView(APIView):
    """API view for network overview dashboard"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        # Active hosts (seen in last 24 hours)
        active_hosts = DiscoveredHost.objects.filter(
            last_seen__gte=timezone.now() - timedelta(hours=24)
        ).count()
        
        # Total open ports
        total_ports_open = DiscoveredPort.objects.filter(state='open').count()
        
        # Recent scans (last 7 days)
        recent_scans = NetworkScan.objects.filter(
            started_at__gte=timezone.now() - timedelta(days=7)
        ).count()
        
        # Active alerts
        active_alerts = NetworkAlert.objects.filter(status='open').count()
        
        # Top services
        top_services = list(DiscoveredPort.objects.filter(
            state='open'
        ).values('service_name').annotate(
            count=Count('id')
        ).order_by('-count')[:10])
        
        # Vulnerability breakdown
        vulnerability_breakdown = {
            'critical': Vulnerability.objects.filter(severity='critical').count(),
            'high': Vulnerability.objects.filter(severity='high').count(),
            'medium': Vulnerability.objects.filter(severity='medium').count(),
            'low': Vulnerability.objects.filter(severity='low').count(),
            'info': Vulnerability.objects.filter(severity='info').count(),
        }
        
        # Traffic summary (last hour)
        one_hour_ago = timezone.now() - timedelta(hours=1)
        traffic_summary = {
            'total_packets': NetworkTraffic.objects.filter(timestamp__gte=one_hour_ago).count(),
            'unique_sources': NetworkTraffic.objects.filter(
                timestamp__gte=one_hour_ago
            ).values('source_ip').distinct().count(),
            'unique_destinations': NetworkTraffic.objects.filter(
                timestamp__gte=one_hour_ago
            ).values('destination_ip').distinct().count(),
        }
        
        overview = {
            'active_hosts': active_hosts,
            'total_ports_open': total_ports_open,
            'recent_scans': recent_scans,
            'active_alerts': active_alerts,
            'top_services': top_services,
            'vulnerability_breakdown': vulnerability_breakdown,
            'traffic_summary': traffic_summary,
        }
        
        serializer = NetworkOverviewSerializer(overview)
        return Response(serializer.data)

class QuickScanView(APIView):
    """API view for quick network scans"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = QuickScanRequestSerializer(data=request.data)
        if serializer.is_valid():
            # Create target and scan
            target_data = serializer.validated_data
            name = target_data.get('name', f"Quick scan - {target_data['target']}")
            
            target = NetworkTarget.objects.create(
                name=name,
                target=target_data['target'],
                scan_type=target_data['scan_type'],
                ports=target_data['ports'],
                created_by=request.user
            )
            
            scan = NetworkScan.objects.create(
                target=target,
                initiated_by=request.user,
                status='running',
                started_at=timezone.now()
            )
            
            # Start scan in background
            def run_scan():
                service = NetworkScanningService()
                service.start_scan(scan.id)
            
            thread = threading.Thread(target=run_scan)
            thread.daemon = True
            thread.start()
            
            scan_serializer = NetworkScanSerializer(scan)
            return Response(scan_serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
