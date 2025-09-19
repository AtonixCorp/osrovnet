"""
Infrastructure Health Monitoring Service
"""
import logging
import threading
import time
import psutil
import socket
import subprocess
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from django.utils import timezone
from django.db import transaction
from .models import (
    InfrastructureComponent, HealthMetric, SystemAlert, 
    PerformanceMetric, MaintenanceWindow
)

logger = logging.getLogger(__name__)

class HealthMonitoringService:
    """Service for monitoring infrastructure health and performance"""
    
    def __init__(self):
        self.monitoring_active = False
        self.monitoring_thread = None
        self.check_interval = 60  # seconds
        
    def start_monitoring(self):
        """Start the health monitoring service"""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
            logger.info("Health monitoring service started")
    
    def stop_monitoring(self):
        """Stop the health monitoring service"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=10)
        logger.info("Health monitoring service stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self._perform_health_checks()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.check_interval)
    
    def _perform_health_checks(self):
        """Perform health checks on all monitored components"""
        components = InfrastructureComponent.objects.filter(is_monitored=True)
        
        for component in components:
            try:
                self._check_component_health(component)
            except Exception as e:
                logger.error(f"Error checking component {component.name}: {e}")
    
    def _check_component_health(self, component: InfrastructureComponent):
        """Check health of a specific component"""
        component.last_check = timezone.now()
        
        # Collect metrics based on component type
        metrics = []
        
        if component.component_type == 'server':
            metrics.extend(self._collect_server_metrics(component))
        elif component.component_type == 'database':
            metrics.extend(self._collect_database_metrics(component))
        elif component.component_type == 'web_server':
            metrics.extend(self._collect_web_server_metrics(component))
        elif component.component_type == 'application':
            metrics.extend(self._collect_application_metrics(component))
        elif component.component_type == 'network':
            metrics.extend(self._collect_network_metrics(component))
        
        # Store metrics
        for metric_data in metrics:
            self._store_metric(component, metric_data)
        
        # Update component status
        self._update_component_status(component, metrics)
        component.save()
    
    def _collect_server_metrics(self, component: InfrastructureComponent) -> List[Dict]:
        """Collect server system metrics"""
        metrics = []
        
        try:
            # CPU Usage
            cpu_percent = psutil.cpu_percent(interval=1)
            metrics.append({
                'metric_type': 'cpu_usage',
                'metric_name': 'CPU Usage',
                'value': cpu_percent,
                'unit': '%',
                'threshold_warning': 80,
                'threshold_critical': 95
            })
            
            # Memory Usage
            memory = psutil.virtual_memory()
            metrics.append({
                'metric_type': 'memory_usage',
                'metric_name': 'Memory Usage',
                'value': memory.percent,
                'unit': '%',
                'threshold_warning': 80,
                'threshold_critical': 95
            })
            
            # Disk Usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            metrics.append({
                'metric_type': 'disk_usage',
                'metric_name': 'Disk Usage',
                'value': disk_percent,
                'unit': '%',
                'threshold_warning': 80,
                'threshold_critical': 95
            })
            
            # Network I/O
            net_io = psutil.net_io_counters()
            metrics.append({
                'metric_type': 'network_io',
                'metric_name': 'Network Bytes Sent',
                'value': net_io.bytes_sent,
                'unit': 'bytes'
            })
            
            metrics.append({
                'metric_type': 'network_io',
                'metric_name': 'Network Bytes Received',
                'value': net_io.bytes_recv,
                'unit': 'bytes'
            })
            
            # Load Average (Linux only)
            try:
                load_avg = psutil.getloadavg()
                metrics.append({
                    'metric_type': 'cpu_usage',
                    'metric_name': 'Load Average (1m)',
                    'value': load_avg[0],
                    'unit': '',
                    'threshold_warning': 2.0,
                    'threshold_critical': 4.0
                })
            except AttributeError:
                pass  # Not available on all platforms
                
        except Exception as e:
            logger.error(f"Error collecting server metrics for {component.name}: {e}")
            
        return metrics
    
    def _collect_database_metrics(self, component: InfrastructureComponent) -> List[Dict]:
        """Collect database metrics"""
        metrics = []
        
        try:
            # Test database connectivity
            response_time = self._test_database_connection(component)
            if response_time is not None:
                metrics.append({
                    'metric_type': 'response_time',
                    'metric_name': 'Database Response Time',
                    'value': response_time,
                    'unit': 'ms',
                    'threshold_warning': 1000,
                    'threshold_critical': 5000
                })
            
            # Additional database-specific metrics would go here
            # (requires database-specific implementation)
            
        except Exception as e:
            logger.error(f"Error collecting database metrics for {component.name}: {e}")
            
        return metrics
    
    def _collect_web_server_metrics(self, component: InfrastructureComponent) -> List[Dict]:
        """Collect web server metrics"""
        metrics = []
        
        try:
            # HTTP response time and status
            response_time, status_code = self._test_http_endpoint(component)
            
            if response_time is not None:
                metrics.append({
                    'metric_type': 'response_time',
                    'metric_name': 'HTTP Response Time',
                    'value': response_time,
                    'unit': 'ms',
                    'threshold_warning': 2000,
                    'threshold_critical': 10000
                })
            
            if status_code is not None:
                metrics.append({
                    'metric_type': 'uptime',
                    'metric_name': 'HTTP Status',
                    'value': 1 if status_code == 200 else 0,
                    'unit': 'status',
                    'metadata': {'status_code': status_code}
                })
                
        except Exception as e:
            logger.error(f"Error collecting web server metrics for {component.name}: {e}")
            
        return metrics
    
    def _collect_application_metrics(self, component: InfrastructureComponent) -> List[Dict]:
        """Collect application-specific metrics"""
        metrics = []
        
        try:
            # Port connectivity test
            if component.port:
                is_reachable = self._test_port_connectivity(
                    component.ip_address or component.hostname, 
                    component.port
                )
                metrics.append({
                    'metric_type': 'uptime',
                    'metric_name': 'Port Connectivity',
                    'value': 1 if is_reachable else 0,
                    'unit': 'status'
                })
                
        except Exception as e:
            logger.error(f"Error collecting application metrics for {component.name}: {e}")
            
        return metrics
    
    def _collect_network_metrics(self, component: InfrastructureComponent) -> List[Dict]:
        """Collect network device metrics"""
        metrics = []
        
        try:
            # Ping test
            if component.ip_address:
                ping_time = self._ping_host(component.ip_address)
                if ping_time is not None:
                    metrics.append({
                        'metric_type': 'response_time',
                        'metric_name': 'Ping Response Time',
                        'value': ping_time,
                        'unit': 'ms',
                        'threshold_warning': 100,
                        'threshold_critical': 1000
                    })
                    
        except Exception as e:
            logger.error(f"Error collecting network metrics for {component.name}: {e}")
            
        return metrics
    
    def _store_metric(self, component: InfrastructureComponent, metric_data: Dict):
        """Store a health metric in the database"""
        try:
            metric = HealthMetric.objects.create(
                component=component,
                **metric_data
            )
            
            # Check thresholds and create alerts if necessary
            self._check_metric_thresholds(metric)
            
        except Exception as e:
            logger.error(f"Error storing metric for {component.name}: {e}")
    
    def _check_metric_thresholds(self, metric: HealthMetric):
        """Check if metric exceeds thresholds and create alerts"""
        try:
            severity = None
            
            if metric.threshold_critical and metric.value >= metric.threshold_critical:
                severity = 'critical'
            elif metric.threshold_warning and metric.value >= metric.threshold_warning:
                severity = 'high'
            
            if severity:
                # Check if similar alert already exists
                existing_alert = SystemAlert.objects.filter(
                    component=metric.component,
                    alert_type='performance',
                    status__in=['open', 'acknowledged'],
                    title__icontains=metric.metric_name
                ).first()
                
                if not existing_alert:
                    SystemAlert.objects.create(
                        component=metric.component,
                        alert_type='performance',
                        severity=severity,
                        title=f"{metric.metric_name} threshold exceeded",
                        message=f"{metric.metric_name} is {metric.value}{metric.unit}, exceeding {severity} threshold",
                        metric=metric
                    )
                    
        except Exception as e:
            logger.error(f"Error checking metric thresholds: {e}")
    
    def _update_component_status(self, component: InfrastructureComponent, metrics: List[Dict]):
        """Update component status based on collected metrics"""
        try:
            # Check for critical alerts
            critical_alerts = SystemAlert.objects.filter(
                component=component,
                severity='critical',
                status__in=['open', 'acknowledged']
            ).count()
            
            if critical_alerts > 0:
                component.status = 'critical'
                return
            
            # Check for warning alerts
            warning_alerts = SystemAlert.objects.filter(
                component=component,
                severity__in=['high', 'medium'],
                status__in=['open', 'acknowledged']
            ).count()
            
            if warning_alerts > 0:
                component.status = 'warning'
                return
            
            # Check if component is in maintenance
            maintenance = MaintenanceWindow.objects.filter(
                components=component,
                status='in_progress',
                scheduled_start__lte=timezone.now(),
                scheduled_end__gte=timezone.now()
            ).exists()
            
            if maintenance:
                component.status = 'maintenance'
                return
            
            # Default to healthy if no issues
            component.status = 'healthy'
            
        except Exception as e:
            logger.error(f"Error updating component status: {e}")
    
    def _test_database_connection(self, component: InfrastructureComponent) -> Optional[float]:
        """Test database connection and measure response time"""
        try:
            start_time = time.time()
            
            # This is a simplified test - in production, you'd use proper database clients
            if component.port:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                result = sock.connect_ex((component.ip_address or component.hostname, component.port))
                sock.close()
                
                if result == 0:
                    return (time.time() - start_time) * 1000
                    
        except Exception:
            pass
            
        return None
    
    def _test_http_endpoint(self, component: InfrastructureComponent) -> tuple:
        """Test HTTP endpoint and measure response time"""
        try:
            url = f"http://{component.ip_address or component.hostname}"
            if component.port and component.port != 80:
                url += f":{component.port}"
                
            start_time = time.time()
            response = requests.get(url, timeout=10)
            response_time = (time.time() - start_time) * 1000
            
            return response_time, response.status_code
            
        except Exception:
            return None, None
    
    def _test_port_connectivity(self, host: str, port: int) -> bool:
        """Test if a port is reachable"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _ping_host(self, host: str) -> Optional[float]:
        """Ping a host and return response time in milliseconds"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '5', host],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Parse ping output to extract time
                output = result.stdout
                if 'time=' in output:
                    time_str = output.split('time=')[1].split()[0]
                    return float(time_str)
                    
        except Exception:
            pass
            
        return None
    
    def get_system_overview(self) -> Dict[str, Any]:
        """Get overall system health overview"""
        try:
            total_components = InfrastructureComponent.objects.filter(is_monitored=True).count()
            healthy_components = InfrastructureComponent.objects.filter(
                is_monitored=True, status='healthy'
            ).count()
            warning_components = InfrastructureComponent.objects.filter(
                is_monitored=True, status='warning'
            ).count()
            critical_components = InfrastructureComponent.objects.filter(
                is_monitored=True, status='critical'
            ).count()
            down_components = InfrastructureComponent.objects.filter(
                is_monitored=True, status='down'
            ).count()
            
            open_alerts = SystemAlert.objects.filter(status__in=['open', 'acknowledged']).count()
            critical_alerts = SystemAlert.objects.filter(
                status__in=['open', 'acknowledged'], severity='critical'
            ).count()
            
            return {
                'total_components': total_components,
                'healthy_components': healthy_components,
                'warning_components': warning_components,
                'critical_components': critical_components,
                'down_components': down_components,
                'health_percentage': (healthy_components / total_components * 100) if total_components > 0 else 0,
                'open_alerts': open_alerts,
                'critical_alerts': critical_alerts,
                'last_updated': timezone.now()
            }
            
        except Exception as e:
            logger.error(f"Error getting system overview: {e}")
            return {}
    
    def get_component_metrics(self, component_id: int, hours: int = 24) -> List[Dict]:
        """Get metrics for a specific component over time"""
        try:
            since = timezone.now() - timedelta(hours=hours)
            metrics = HealthMetric.objects.filter(
                component_id=component_id,
                timestamp__gte=since
            ).order_by('timestamp')
            
            return [
                {
                    'timestamp': metric.timestamp,
                    'metric_type': metric.metric_type,
                    'metric_name': metric.metric_name,
                    'value': metric.value,
                    'unit': metric.unit
                }
                for metric in metrics
            ]
            
        except Exception as e:
            logger.error(f"Error getting component metrics: {e}")
            return []

# Global instance
health_monitoring_service = HealthMonitoringService()