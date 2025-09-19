"""
Infrastructure Resilience API Views
"""
import logging
from datetime import timedelta
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import (
    InfrastructureComponent, HealthMetric, SystemAlert, BackupJob, 
    BackupExecution, PerformanceMetric, DisasterRecoveryPlan, 
    DisasterRecoveryTest, MaintenanceWindow
)
from .serializers import (
    InfrastructureComponentSerializer, HealthMetricSerializer, SystemAlertSerializer,
    BackupJobSerializer, BackupExecutionSerializer, PerformanceMetricSerializer,
    DisasterRecoveryPlanSerializer, DisasterRecoveryTestSerializer, 
    MaintenanceWindowSerializer, SystemOverviewSerializer, ComponentMetricsSerializer
)
from .health_service import health_monitoring_service
from .backup_service import backup_service

logger = logging.getLogger(__name__)

class InfrastructureComponentViewSet(viewsets.ModelViewSet):
    """ViewSet for infrastructure components"""
    
    queryset = InfrastructureComponent.objects.all()
    serializer_class = InfrastructureComponentSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter components based on query parameters"""
        queryset = super().get_queryset()
        
        component_type = self.request.query_params.get('type')
        status_filter = self.request.query_params.get('status')
        is_monitored = self.request.query_params.get('monitored')
        
        if component_type:
            queryset = queryset.filter(component_type=component_type)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if is_monitored is not None:
            queryset = queryset.filter(is_monitored=is_monitored.lower() == 'true')
            
        return queryset.order_by('-created_at')
    
    @action(detail=True, methods=['get'])
    def metrics(self, request, pk=None):
        """Get metrics for a specific component"""
        component = self.get_object()
        hours = int(request.query_params.get('hours', 24))
        
        metrics_data = health_monitoring_service.get_component_metrics(component.id, hours)
        serializer = ComponentMetricsSerializer(metrics_data, many=True)
        
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def alerts(self, request, pk=None):
        """Get alerts for a specific component"""
        component = self.get_object()
        
        alerts = SystemAlert.objects.filter(component=component).order_by('-created_at')[:50]
        serializer = SystemAlertSerializer(alerts, many=True)
        
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def check_health(self, request, pk=None):
        """Manually trigger health check for a component"""
        component = self.get_object()
        
        try:
            health_monitoring_service._check_component_health(component)
            return Response({'message': 'Health check completed'})
        except Exception as e:
            logger.error(f"Manual health check failed for {component.name}: {e}")
            return Response(
                {'error': 'Health check failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class HealthMetricViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for health metrics"""
    
    queryset = HealthMetric.objects.all()
    serializer_class = HealthMetricSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter metrics based on query parameters"""
        queryset = super().get_queryset()
        
        component_id = self.request.query_params.get('component')
        metric_type = self.request.query_params.get('type')
        hours = self.request.query_params.get('hours', 24)
        
        # Filter by time range
        since = timezone.now() - timedelta(hours=int(hours))
        queryset = queryset.filter(timestamp__gte=since)
        
        if component_id:
            queryset = queryset.filter(component_id=component_id)
        if metric_type:
            queryset = queryset.filter(metric_type=metric_type)
            
        return queryset.order_by('-timestamp')

class SystemAlertViewSet(viewsets.ModelViewSet):
    """ViewSet for system alerts"""
    
    queryset = SystemAlert.objects.all()
    serializer_class = SystemAlertSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter alerts based on query parameters"""
        queryset = super().get_queryset()
        
        severity = self.request.query_params.get('severity')
        status_filter = self.request.query_params.get('status')
        alert_type = self.request.query_params.get('type')
        component_id = self.request.query_params.get('component')
        
        if severity:
            queryset = queryset.filter(severity=severity)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if alert_type:
            queryset = queryset.filter(alert_type=alert_type)
        if component_id:
            queryset = queryset.filter(component_id=component_id)
            
        return queryset.order_by('-created_at')
    
    @action(detail=True, methods=['post'])
    def acknowledge(self, request, pk=None):
        """Acknowledge an alert"""
        alert = self.get_object()
        
        if alert.status == 'open':
            alert.status = 'acknowledged'
            alert.acknowledged_at = timezone.now()
            alert.acknowledged_by = request.user
            alert.save()
            
            return Response({'message': 'Alert acknowledged'})
        else:
            return Response(
                {'error': 'Alert cannot be acknowledged'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """Resolve an alert"""
        alert = self.get_object()
        
        if alert.status in ['open', 'acknowledged', 'investigating']:
            alert.status = 'resolved'
            alert.resolved_at = timezone.now()
            alert.resolved_by = request.user
            alert.save()
            
            return Response({'message': 'Alert resolved'})
        else:
            return Response(
                {'error': 'Alert cannot be resolved'},
                status=status.HTTP_400_BAD_REQUEST
            )

class BackupJobViewSet(viewsets.ModelViewSet):
    """ViewSet for backup jobs"""
    
    queryset = BackupJob.objects.all()
    serializer_class = BackupJobSerializer
    permission_classes = [IsAuthenticated]
    
    def perform_create(self, serializer):
        """Set created_by to current user"""
        serializer.save(created_by=self.request.user)
    
    @action(detail=True, methods=['post'])
    def execute(self, request, pk=None):
        """Execute a backup job"""
        backup_job = self.get_object()
        
        try:
            execution = backup_service.execute_backup(backup_job)
            serializer = BackupExecutionSerializer(execution)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Backup execution failed: {e}")
            return Response(
                {'error': 'Backup execution failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'])
    def executions(self, request, pk=None):
        """Get executions for a backup job"""
        backup_job = self.get_object()
        
        executions = backup_job.executions.order_by('-started_at')[:20]
        serializer = BackupExecutionSerializer(executions, many=True)
        
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def cleanup(self, request, pk=None):
        """Clean up old backups"""
        backup_job = self.get_object()
        
        try:
            backup_service.cleanup_old_backups(backup_job)
            return Response({'message': 'Old backups cleaned up'})
        except Exception as e:
            logger.error(f"Backup cleanup failed: {e}")
            return Response(
                {'error': 'Backup cleanup failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class BackupExecutionViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for backup executions"""
    
    queryset = BackupExecution.objects.all()
    serializer_class = BackupExecutionSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter executions based on query parameters"""
        queryset = super().get_queryset()
        
        backup_job_id = self.request.query_params.get('job')
        status_filter = self.request.query_params.get('status')
        
        if backup_job_id:
            queryset = queryset.filter(backup_job_id=backup_job_id)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
            
        return queryset.order_by('-started_at')
    
    @action(detail=True, methods=['post'])
    def restore(self, request, pk=None):
        """Restore from a backup execution"""
        execution = self.get_object()
        restore_path = request.data.get('restore_path')
        
        try:
            success = backup_service.restore_backup(execution, restore_path)
            if success:
                return Response({'message': 'Restore completed successfully'})
            else:
                return Response(
                    {'error': 'Restore failed'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return Response(
                {'error': 'Restore failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        """Verify backup integrity"""
        execution = self.get_object()
        
        try:
            is_valid = backup_service.verify_backup(execution)
            return Response({'valid': is_valid})
        except Exception as e:
            logger.error(f"Backup verification failed: {e}")
            return Response(
                {'error': 'Verification failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class PerformanceMetricViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for performance metrics"""
    
    queryset = PerformanceMetric.objects.all()
    serializer_class = PerformanceMetricSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter performance metrics based on query parameters"""
        queryset = super().get_queryset()
        
        category = self.request.query_params.get('category')
        metric_name = self.request.query_params.get('metric')
        component_id = self.request.query_params.get('component')
        hours = self.request.query_params.get('hours', 24)
        
        # Filter by time range
        since = timezone.now() - timedelta(hours=int(hours))
        queryset = queryset.filter(timestamp__gte=since)
        
        if category:
            queryset = queryset.filter(category=category)
        if metric_name:
            queryset = queryset.filter(metric_name=metric_name)
        if component_id:
            queryset = queryset.filter(component_id=component_id)
            
        return queryset.order_by('-timestamp')

class DisasterRecoveryPlanViewSet(viewsets.ModelViewSet):
    """ViewSet for disaster recovery plans"""
    
    queryset = DisasterRecoveryPlan.objects.all()
    serializer_class = DisasterRecoveryPlanSerializer
    permission_classes = [IsAuthenticated]
    
    def perform_create(self, serializer):
        """Set created_by to current user"""
        serializer.save(created_by=self.request.user)
    
    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve a disaster recovery plan"""
        plan = self.get_object()
        
        if plan.status == 'draft':
            plan.status = 'approved'
            plan.approved_by = request.user
            plan.save()
            
            return Response({'message': 'Plan approved'})
        else:
            return Response(
                {'error': 'Plan cannot be approved'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        """Activate a disaster recovery plan"""
        plan = self.get_object()
        
        if plan.status == 'approved':
            plan.status = 'active'
            plan.save()
            
            return Response({'message': 'Plan activated'})
        else:
            return Response(
                {'error': 'Plan cannot be activated'},
                status=status.HTTP_400_BAD_REQUEST
            )

class DisasterRecoveryTestViewSet(viewsets.ModelViewSet):
    """ViewSet for disaster recovery tests"""
    
    queryset = DisasterRecoveryTest.objects.all()
    serializer_class = DisasterRecoveryTestSerializer
    permission_classes = [IsAuthenticated]
    
    def perform_create(self, serializer):
        """Set test_lead to current user"""
        serializer.save(test_lead=self.request.user)
    
    @action(detail=True, methods=['post'])
    def start(self, request, pk=None):
        """Start a disaster recovery test"""
        test = self.get_object()
        
        if test.status == 'planned':
            test.status = 'in_progress'
            test.started_at = timezone.now()
            test.save()
            
            return Response({'message': 'Test started'})
        else:
            return Response(
                {'error': 'Test cannot be started'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=True, methods=['post'])
    def complete(self, request, pk=None):
        """Complete a disaster recovery test"""
        test = self.get_object()
        
        if test.status == 'in_progress':
            test.status = 'completed'
            test.completed_at = timezone.now()
            test.duration = test.completed_at - test.started_at
            test.results = request.data.get('results', '')
            test.issues_found = request.data.get('issues_found', [])
            test.recommendations = request.data.get('recommendations', '')
            test.save()
            
            return Response({'message': 'Test completed'})
        else:
            return Response(
                {'error': 'Test cannot be completed'},
                status=status.HTTP_400_BAD_REQUEST
            )

class MaintenanceWindowViewSet(viewsets.ModelViewSet):
    """ViewSet for maintenance windows"""
    
    queryset = MaintenanceWindow.objects.all()
    serializer_class = MaintenanceWindowSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter maintenance windows based on query parameters"""
        queryset = super().get_queryset()
        
        status_filter = self.request.query_params.get('status')
        upcoming = self.request.query_params.get('upcoming')
        
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if upcoming and upcoming.lower() == 'true':
            queryset = queryset.filter(
                scheduled_start__gte=timezone.now(),
                status='scheduled'
            )
            
        return queryset.order_by('scheduled_start')
    
    @action(detail=True, methods=['post'])
    def start(self, request, pk=None):
        """Start a maintenance window"""
        maintenance = self.get_object()
        
        if maintenance.status == 'scheduled':
            maintenance.status = 'in_progress'
            maintenance.actual_start = timezone.now()
            maintenance.save()
            
            return Response({'message': 'Maintenance started'})
        else:
            return Response(
                {'error': 'Maintenance cannot be started'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=True, methods=['post'])
    def complete(self, request, pk=None):
        """Complete a maintenance window"""
        maintenance = self.get_object()
        
        if maintenance.status == 'in_progress':
            maintenance.status = 'completed'
            maintenance.actual_end = timezone.now()
            maintenance.save()
            
            return Response({'message': 'Maintenance completed'})
        else:
            return Response(
                {'error': 'Maintenance cannot be completed'},
                status=status.HTTP_400_BAD_REQUEST
            )

# System overview endpoint
def system_overview(request):
    """Get system overview dashboard data"""
    try:
        overview_data = health_monitoring_service.get_system_overview()
        serializer = SystemOverviewSerializer(overview_data)
        return JsonResponse(serializer.data)
    except Exception as e:
        logger.error(f"Error getting system overview: {e}")
        return JsonResponse({'error': 'Failed to get system overview'}, status=500)