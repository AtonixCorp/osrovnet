"""
Complete Infrastructure Resilience Demo
"""
import os
import sys
import django
import time
import json
from datetime import datetime, timedelta

# Setup Django
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'osrovnet.settings')
django.setup()

from django.contrib.auth.models import User
from infrastructure.models import (
    InfrastructureComponent, HealthMetric, SystemAlert, 
    BackupJob, BackupExecution, PerformanceMetric,
    DisasterRecoveryPlan, DisasterRecoveryTest, MaintenanceWindow
)
from infrastructure.health_service import health_monitoring_service
from infrastructure.backup_service import backup_service

def demo_infrastructure_resilience():
    """Complete demo of infrastructure resilience features"""
    print("🔧" + "=" * 70)
    print("  OSROVNET INFRASTRUCTURE RESILIENCE DEMONSTRATION")
    print("=" * 72)
    
    # Get or create admin user
    user, _ = User.objects.get_or_create(
        username='admin',
        defaults={
            'email': 'admin@osrovnet.com',
            'is_staff': True,
            'is_superuser': True
        }
    )
    
    print("\n📊 INFRASTRUCTURE MONITORING DASHBOARD")
    print("-" * 50)
    
    # Display system overview
    overview = health_monitoring_service.get_system_overview()
    
    print(f"🟢 Total Components: {overview.get('total_components', 0)}")
    print(f"✅ Healthy Components: {overview.get('healthy_components', 0)}")
    print(f"⚠️  Warning Components: {overview.get('warning_components', 0)}")
    print(f"🔴 Critical Components: {overview.get('critical_components', 0)}")
    print(f"📈 Overall Health: {overview.get('health_percentage', 0):.1f}%")
    print(f"🚨 Open Alerts: {overview.get('open_alerts', 0)}")
    
    # Display component details
    print("\n🖥️  INFRASTRUCTURE COMPONENTS")
    print("-" * 50)
    
    components = InfrastructureComponent.objects.all()
    for component in components:
        status_icon = {
            'healthy': '🟢',
            'warning': '🟡',
            'critical': '🔴',
            'down': '🔴',
            'maintenance': '🔧'
        }.get(component.status, '❓')
        
        print(f"{status_icon} {component.name}")
        print(f"   Type: {component.get_component_type_display()}")
        print(f"   Status: {component.get_status_display()}")
        if component.ip_address:
            print(f"   Address: {component.ip_address}:{component.port or 'N/A'}")
        print(f"   Critical: {'Yes' if component.is_critical else 'No'}")
        print(f"   Last Check: {component.last_check or 'Never'}")
        print()
    
    # Display recent metrics
    print("\n📈 PERFORMANCE METRICS (Last 24 Hours)")
    print("-" * 50)
    
    recent_metrics = HealthMetric.objects.filter(
        timestamp__gte=datetime.now() - timedelta(hours=24)
    ).order_by('-timestamp')[:10]
    
    if recent_metrics:
        for metric in recent_metrics:
            print(f"📊 {metric.component.name}: {metric.metric_name}")
            print(f"   Value: {metric.value} {metric.unit}")
            print(f"   Time: {metric.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            if metric.threshold_warning:
                status = "🔴" if metric.value >= (metric.threshold_critical or 0) else "🟡" if metric.value >= metric.threshold_warning else "🟢"
                print(f"   Status: {status}")
            print()
    else:
        print("   No recent metrics available")
    
    # Display alerts
    print("\n🚨 SYSTEM ALERTS")
    print("-" * 50)
    
    alerts = SystemAlert.objects.filter(
        status__in=['open', 'acknowledged']
    ).order_by('-created_at')[:5]
    
    if alerts:
        for alert in alerts:
            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵',
                'info': 'ℹ️'
            }.get(alert.severity, '❓')
            
            print(f"{severity_icon} {alert.title}")
            print(f"   Component: {alert.component.name}")
            print(f"   Severity: {alert.get_severity_display()}")
            print(f"   Status: {alert.get_status_display()}")
            print(f"   Created: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
            print()
    else:
        print("   🎉 No active alerts!")
    
    # Display backup status
    print("\n💾 BACKUP MANAGEMENT")
    print("-" * 50)
    
    backup_jobs = BackupJob.objects.all()
    for job in backup_jobs:
        print(f"📦 {job.name}")
        print(f"   Type: {job.get_backup_type_display()}")
        print(f"   Frequency: {job.get_frequency_display()}")
        print(f"   Status: {'Enabled' if job.is_enabled else 'Disabled'}")
        print(f"   Last Run: {job.last_run or 'Never'}")
        
        # Get last execution
        last_execution = job.executions.order_by('-started_at').first()
        if last_execution:
            status_icon = {
                'completed': '✅',
                'failed': '❌',
                'running': '⏳',
                'cancelled': '⏹️'
            }.get(last_execution.status, '❓')
            print(f"   Last Status: {status_icon} {last_execution.get_status_display()}")
            if last_execution.backup_size:
                size_mb = last_execution.backup_size / (1024 * 1024)
                print(f"   Last Size: {size_mb:.2f} MB")
        print()
    
    # Display disaster recovery plans
    print("\n🆘 DISASTER RECOVERY PLANS")
    print("-" * 50)
    
    dr_plans = DisasterRecoveryPlan.objects.all()
    for plan in dr_plans:
        status_icon = {
            'active': '🟢',
            'approved': '✅',
            'draft': '📝',
            'outdated': '⚠️',
            'archived': '📦'
        }.get(plan.status, '❓')
        
        print(f"{status_icon} {plan.name}")
        print(f"   Type: {plan.get_plan_type_display()}")
        print(f"   Status: {plan.get_status_display()}")
        print(f"   Priority: {plan.priority}/5")
        print(f"   RTO: {plan.rto} minutes")
        print(f"   RPO: {plan.rpo} minutes")
        print(f"   Last Tested: {plan.last_tested or 'Never'}")
        print()
    
    # Display maintenance windows
    print("\n🔧 MAINTENANCE WINDOWS")
    print("-" * 50)
    
    maintenance = MaintenanceWindow.objects.filter(
        scheduled_start__gte=datetime.now() - timedelta(days=7)
    ).order_by('scheduled_start')[:5]
    
    if maintenance:
        for window in maintenance:
            status_icon = {
                'scheduled': '📅',
                'in_progress': '⚠️',
                'completed': '✅',
                'cancelled': '❌',
                'failed': '🔴'
            }.get(window.status, '❓')
            
            print(f"{status_icon} {window.title}")
            print(f"   Type: {window.get_maintenance_type_display()}")
            print(f"   Status: {window.get_status_display()}")
            print(f"   Scheduled: {window.scheduled_start.strftime('%Y-%m-%d %H:%M')}")
            print(f"   Assigned: {window.assigned_to.username}")
            print()
    else:
        print("   No upcoming maintenance windows")
    
    # Performance summary
    print("\n📊 PERFORMANCE SUMMARY")
    print("-" * 50)
    
    perf_metrics = PerformanceMetric.objects.filter(
        timestamp__gte=datetime.now() - timedelta(hours=1)
    ).order_by('-timestamp')[:5]
    
    if perf_metrics:
        for metric in perf_metrics:
            print(f"⚡ {metric.metric_name}: {metric.value} {metric.unit}")
            print(f"   Category: {metric.get_category_display()}")
            print(f"   Time: {metric.timestamp.strftime('%H:%M:%S')}")
            print()
    else:
        print("   No recent performance metrics")
    
    # System health recommendations
    print("\n💡 RECOMMENDATIONS")
    print("-" * 50)
    
    recommendations = []
    
    # Check for critical components without recent checks
    old_checks = InfrastructureComponent.objects.filter(
        is_critical=True,
        last_check__lt=datetime.now() - timedelta(hours=2)
    ).count()
    
    if old_checks > 0:
        recommendations.append(f"⚠️  {old_checks} critical components haven't been checked recently")
    
    # Check for failed backups
    failed_backups = BackupExecution.objects.filter(
        status='failed',
        started_at__gte=datetime.now() - timedelta(days=1)
    ).count()
    
    if failed_backups > 0:
        recommendations.append(f"❌ {failed_backups} backup failures in the last 24 hours")
    
    # Check for outdated DR plans
    outdated_plans = DisasterRecoveryPlan.objects.filter(
        last_tested__lt=datetime.now() - timedelta(days=90)
    ).count()
    
    if outdated_plans > 0:
        recommendations.append(f"📋 {outdated_plans} DR plans need testing (>90 days)")
    
    # Check for high-severity alerts
    critical_alerts = SystemAlert.objects.filter(
        severity='critical',
        status__in=['open', 'acknowledged']
    ).count()
    
    if critical_alerts > 0:
        recommendations.append(f"🚨 {critical_alerts} critical alerts require immediate attention")
    
    if recommendations:
        for rec in recommendations:
            print(f"   {rec}")
    else:
        print("   🎉 All systems are operating optimally!")
    
    print("\n" + "=" * 72)
    print("  INFRASTRUCTURE RESILIENCE DEMONSTRATION COMPLETE")
    print("🔧" + "=" * 70)
    
    print("\n📋 QUICK STATS:")
    print(f"   • Components Monitored: {InfrastructureComponent.objects.filter(is_monitored=True).count()}")
    print(f"   • Active Backup Jobs: {BackupJob.objects.filter(is_enabled=True).count()}")
    print(f"   • DR Plans Ready: {DisasterRecoveryPlan.objects.filter(status='active').count()}")
    print(f"   • System Health: {overview.get('health_percentage', 0):.1f}%")
    
    print("\n🔗 API ENDPOINTS AVAILABLE:")
    print("   • GET  /api/infrastructure/overview/")
    print("   • GET  /api/infrastructure/components/")
    print("   • GET  /api/infrastructure/alerts/")
    print("   • GET  /api/infrastructure/backup-jobs/")
    print("   • GET  /api/infrastructure/dr-plans/")
    
    print("\n📚 DOCUMENTATION:")
    print("   • Infrastructure Guide: docs/infrastructure-resilience-guide.md")
    print("   • API Documentation: docs/api.md")
    print("   • Development Guide: docs/development.md")

if __name__ == "__main__":
    demo_infrastructure_resilience()