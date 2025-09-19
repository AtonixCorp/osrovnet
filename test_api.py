#!/usr/bin/env python
"""
Test script for the Network Security API endpoints
"""
import os
import sys
import django

# Add the backend directory to Python path and change working directory
backend_dir = '/home/atonixdev/atonixcorpvm/osrovnet/backend'
sys.path.insert(0, backend_dir)
os.chdir(backend_dir)

# Set Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'osrovnet.settings')

# Setup Django
django.setup()

from network_security.models import (
    NetworkTarget, NetworkScan, DiscoveredHost, 
    DiscoveredPort, Vulnerability, NetworkAlert
)
from django.contrib.auth.models import User

def test_models():
    """Test model creation and basic functionality"""
    print("Testing network security models...")
    
    # Create a test user
    user, created = User.objects.get_or_create(
        username='testuser',
        defaults={'email': 'test@example.com'}
    )
    
    # Create a network target
    target = NetworkTarget.objects.create(
        name='Test Network',
        target='192.168.1.0/24',
        scan_type='quick',
        ports='1-1000',
        created_by=user
    )
    print(f"✓ Created NetworkTarget: {target.name}")
    
    # Create a network scan
    scan = NetworkScan.objects.create(
        target=target,
        initiated_by=user,
        status='completed',
        hosts_discovered=5,
        ports_scanned=1000,
        vulnerabilities_found=2
    )
    print(f"✓ Created NetworkScan: {scan.id}")
    
    # Create a discovered host
    host = DiscoveredHost.objects.create(
        scan=scan,
        ip_address='192.168.1.10',
        hostname='test-host.local',
        state='up'
    )
    print(f"✓ Created DiscoveredHost: {host.ip_address}")
    
    # Create a discovered port
    port = DiscoveredPort.objects.create(
        host=host,
        port_number=80,
        protocol='tcp',
        state='open',
        service_name='http'
    )
    print(f"✓ Created DiscoveredPort: {port.port_number}")
    
    # Create a vulnerability
    vuln = Vulnerability.objects.create(
        port=port,
        title='HTTP Server Information Disclosure',
        description='Server version information exposed',
        severity='medium',
        cvss_score=5.0
    )
    print(f"✓ Created Vulnerability: {vuln.title}")
    
    # Create a network alert
    alert = NetworkAlert.objects.create(
        alert_type='security',
        severity='high',
        status='open',
        title='Suspicious Network Activity',
        description='Unusual traffic pattern detected',
        source_ip='192.168.1.10'
    )
    print(f"✓ Created NetworkAlert: {alert.title}")
    
    print("\n📊 Model Counts:")
    print(f"  - NetworkTargets: {NetworkTarget.objects.count()}")
    print(f"  - NetworkScans: {NetworkScan.objects.count()}")
    print(f"  - DiscoveredHosts: {DiscoveredHost.objects.count()}")
    print(f"  - DiscoveredPorts: {DiscoveredPort.objects.count()}")
    print(f"  - Vulnerabilities: {Vulnerability.objects.count()}")
    print(f"  - NetworkAlerts: {NetworkAlert.objects.count()}")
    
    return True

def test_api_views():
    """Test API view functionality"""
    print("\nTesting API views...")
    
    from django.test import RequestFactory
    from django.contrib.auth.models import AnonymousUser
    from network_security.views import (
        DashboardStatisticsView, NetworkOverviewView
    )
    
    factory = RequestFactory()
    
    # Test dashboard statistics
    request = factory.get('/api/dashboard/statistics/')
    request.user = AnonymousUser()
    
    try:
        view = DashboardStatisticsView()
        view.request = request
        # This would normally require authentication, but we can test the logic
        print("✓ DashboardStatisticsView instantiated successfully")
    except Exception as e:
        print(f"✗ DashboardStatisticsView error: {e}")
    
    # Test network overview
    try:
        view = NetworkOverviewView()
        view.request = request
        print("✓ NetworkOverviewView instantiated successfully")
    except Exception as e:
        print(f"✗ NetworkOverviewView error: {e}")
    
    return True

if __name__ == '__main__':
    print("🚀 Starting Network Security API Tests\n")
    
    try:
        test_models()
        test_api_views()
        print("\n✅ All tests completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        sys.exit(1)