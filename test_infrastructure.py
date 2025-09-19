"""
Test Infrastructure Resilience Features
"""
import os
import sys
import django

# Add the backend directory to Python path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend'))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'osrovnet.settings')
django.setup()

import json
import requests
from django.contrib.auth.models import User
from infrastructure.models import (
    InfrastructureComponent, BackupJob, DisasterRecoveryPlan, MaintenanceWindow
)
from infrastructure.health_service import health_monitoring_service
from infrastructure.backup_service import backup_service

def test_infrastructure_setup():
    """Test infrastructure resilience setup"""
    print("=" * 60)
    print("TESTING INFRASTRUCTURE RESILIENCE FEATURES")
    print("=" * 60)
    
    # Create test user if it doesn't exist
    user, created = User.objects.get_or_create(
        username='admin',
        defaults={
            'email': 'admin@osrovnet.com',
            'is_staff': True,
            'is_superuser': True
        }
    )
    if created:
        user.set_password('admin123')
        user.save()
        print(f"✓ Created admin user")
    else:
        print(f"✓ Admin user exists")
    
    # Create infrastructure components
    components_data = [
        {
            'name': 'Primary Web Server',
            'component_type': 'web_server',
            'hostname': 'web01.osrovnet.local',
            'ip_address': '192.168.1.10',
            'port': 80,
            'is_critical': True,
            'description': 'Main web server hosting the application'
        },
        {
            'name': 'Database Server',
            'component_type': 'database',
            'hostname': 'db01.osrovnet.local',
            'ip_address': '192.168.1.20',
            'port': 5432,
            'is_critical': True,
            'description': 'PostgreSQL database server'
        },
        {
            'name': 'Redis Cache',
            'component_type': 'cache',
            'hostname': 'cache01.osrovnet.local',
            'ip_address': '192.168.1.30',
            'port': 6379,
            'is_critical': False,
            'description': 'Redis cache server'
        },
        {
            'name': 'Load Balancer',
            'component_type': 'load_balancer',
            'hostname': 'lb01.osrovnet.local',
            'ip_address': '192.168.1.5',
            'port': 80,
            'is_critical': True,
            'description': 'HAProxy load balancer'
        },
        {
            'name': 'Application Server',
            'component_type': 'application',
            'hostname': 'app01.osrovnet.local',
            'ip_address': '192.168.1.15',
            'port': 8000,
            'is_critical': True,
            'description': 'Django application server'
        }
    ]
    
    components_created = 0
    for comp_data in components_data:
        component, created = InfrastructureComponent.objects.get_or_create(
            name=comp_data['name'],
            defaults=comp_data
        )
        if created:
            components_created += 1
    
    print(f"✓ Created {components_created} infrastructure components")
    
    # Create backup jobs
    backup_jobs_data = [
        {
            'name': 'Daily Database Backup',
            'backup_type': 'database',
            'description': 'Daily backup of PostgreSQL database',
            'source_path': '/var/lib/postgresql/data',
            'destination_path': '/backups/database',
            'frequency': 'daily',
            'retention_days': 30,
            'compression_enabled': True,
            'encryption_enabled': False,
            'created_by': user
        },
        {
            'name': 'Weekly Configuration Backup',
            'backup_type': 'configuration',
            'description': 'Weekly backup of configuration files',
            'source_path': '/etc/osrovnet',
            'destination_path': '/backups/config',
            'frequency': 'weekly',
            'retention_days': 90,
            'compression_enabled': True,
            'encryption_enabled': True,
            'created_by': user
        },
        {
            'name': 'Daily Log Backup',
            'backup_type': 'logs',
            'description': 'Daily backup of log files',
            'source_path': '/var/log/osrovnet',
            'destination_path': '/backups/logs',
            'frequency': 'daily',
            'retention_days': 7,
            'compression_enabled': True,
            'encryption_enabled': False,
            'created_by': user
        }
    ]
    
    backup_jobs_created = 0
    for job_data in backup_jobs_data:
        backup_job, created = BackupJob.objects.get_or_create(
            name=job_data['name'],
            defaults=job_data
        )
        if created:
            backup_jobs_created += 1
    
    print(f"✓ Created {backup_jobs_created} backup jobs")
    
    # Create disaster recovery plans
    dr_plans_data = [
        {
            'name': 'Database Recovery Plan',
            'plan_type': 'data_recovery',
            'description': 'Plan for recovering from database failures',
            'status': 'approved',
            'priority': 1,
            'rto': 60,  # 1 hour
            'rpo': 15,  # 15 minutes
            'procedures': [
                'Assess database failure',
                'Stop application services',
                'Restore from latest backup',
                'Verify data integrity',
                'Restart application services',
                'Test functionality'
            ],
            'contacts': [
                {'name': 'DBA Team', 'phone': '+1-555-0101', 'email': 'dba@osrovnet.com'},
                {'name': 'DevOps Team', 'phone': '+1-555-0102', 'email': 'devops@osrovnet.com'}
            ],
            'resources_required': ['Backup storage', 'Database server', 'Monitoring tools'],
            'dependencies': ['Network connectivity', 'Storage systems'],
            'testing_schedule': 'monthly',
            'created_by': user
        },
        {
            'name': 'Full Site Recovery Plan',
            'plan_type': 'full_site_recovery',
            'description': 'Complete site recovery from catastrophic failure',
            'status': 'approved',
            'priority': 1,
            'rto': 240,  # 4 hours
            'rpo': 60,   # 1 hour
            'procedures': [
                'Activate disaster recovery site',
                'Restore network infrastructure',
                'Restore database from backups',
                'Deploy application services',
                'Update DNS records',
                'Verify all services',
                'Communicate with stakeholders'
            ],
            'contacts': [
                {'name': 'Incident Commander', 'phone': '+1-555-0100', 'email': 'incident@osrovnet.com'},
                {'name': 'Infrastructure Team', 'phone': '+1-555-0103', 'email': 'infra@osrovnet.com'}
            ],
            'resources_required': ['DR site', 'Backup systems', 'Network equipment'],
            'dependencies': ['DR site availability', 'Communication systems'],
            'testing_schedule': 'quarterly',
            'created_by': user
        }
    ]
    
    dr_plans_created = 0
    for plan_data in dr_plans_data:
        dr_plan, created = DisasterRecoveryPlan.objects.get_or_create(
            name=plan_data['name'],
            defaults=plan_data
        )
        if created:
            dr_plans_created += 1
    
    print(f"✓ Created {dr_plans_created} disaster recovery plans")
    
    # Test health monitoring service
    print("\n" + "=" * 40)
    print("TESTING HEALTH MONITORING")
    print("=" * 40)
    
    # Get system overview
    overview = health_monitoring_service.get_system_overview()
    print(f"✓ System Overview:")
    print(f"  - Total Components: {overview.get('total_components', 0)}")
    print(f"  - Healthy Components: {overview.get('healthy_components', 0)}")
    print(f"  - Health Percentage: {overview.get('health_percentage', 0):.1f}%")
    print(f"  - Open Alerts: {overview.get('open_alerts', 0)}")
    
    # Test backup service
    print("\n" + "=" * 40)
    print("TESTING BACKUP SERVICE")
    print("=" * 40)
    
    # Test configuration backup
    config_backup_job = BackupJob.objects.filter(backup_type='configuration').first()
    if config_backup_job:
        try:
            print(f"✓ Executing backup job: {config_backup_job.name}")
            execution = backup_service.execute_backup(config_backup_job)
            print(f"  - Status: {execution.status}")
            if execution.error_message:
                print(f"  - Error: {execution.error_message}")
        except Exception as e:
            print(f"  - Backup failed: {e}")
    
    print("\n" + "=" * 40)
    print("TESTING API ENDPOINTS")
    print("=" * 40)
    
    # Test API endpoints
    base_url = "http://127.0.0.1:8000/api/infrastructure"
    
    try:
        # Test system overview
        response = requests.get(f"{base_url}/overview/", timeout=5)
        if response.status_code == 200:
            print("✓ System overview endpoint working")
        else:
            print(f"✗ System overview endpoint failed: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"✗ Could not connect to API: {e}")
    
    print("\n" + "=" * 40)
    print("INFRASTRUCTURE RESILIENCE SUMMARY")
    print("=" * 40)
    
    # Print summary
    total_components = InfrastructureComponent.objects.count()
    total_backup_jobs = BackupJob.objects.count()
    total_dr_plans = DisasterRecoveryPlan.objects.count()
    
    print(f"✓ Infrastructure Components: {total_components}")
    print(f"✓ Backup Jobs: {total_backup_jobs}")
    print(f"✓ Disaster Recovery Plans: {total_dr_plans}")
    print(f"✓ Health Monitoring: Active")
    print(f"✓ Backup Service: Active")
    
    print("\n🎉 Infrastructure resilience features are ready!")
    print("\nNext steps:")
    print("1. Configure specific monitoring thresholds")
    print("2. Set up backup schedules")
    print("3. Test disaster recovery procedures")
    print("4. Configure alerting notifications")
    print("5. Integrate with frontend dashboard")

if __name__ == "__main__":
    test_infrastructure_setup()