#!/usr/bin/env python
"""
Test script for IOC Management System
"""
import os
import sys
import django

# Add the backend directory to Python path
sys.path.append('/home/atonixdev/atonixcorpvm/osrovnet/backend')
os.chdir('/home/atonixdev/atonixcorpvm/osrovnet/backend')

# Set Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'osrovnet.settings')

# Setup Django
django.setup()

from threat_intelligence.models import (
    ThreatFeed, IndicatorOfCompromise, ThreatActor, ThreatCampaign,
    ThreatHunt, ThreatMatch
)
from threat_intelligence.ioc_service import ioc_manager
from django.contrib.auth.models import User
from django.utils import timezone

def test_ioc_management():
    """Test IOC management functionality"""
    print("🧪 Testing IOC Management System\n")
    
    # Create a test user
    user, created = User.objects.get_or_create(
        username='threat_analyst',
        defaults={'email': 'analyst@osrovnet.com'}
    )
    print(f"✓ Created test user: {user.username}")
    
    # Create a threat feed
    feed = ThreatFeed.objects.create(
        name='Test Threat Feed',
        feed_type='custom',
        description='Test feed for IOC management',
        created_by=user
    )
    print(f"✓ Created threat feed: {feed.name}")
    
    # Test IOC creation
    test_iocs = [
        {
            'value': '192.168.1.100',
            'ioc_type': 'ip',
            'threat_type': 'malware',
            'severity': 'high',
            'description': 'Malicious IP address',
            'tags': ['malware', 'c2']
        },
        {
            'value': 'malicious.example.com',
            'ioc_type': 'domain',
            'threat_type': 'phishing',
            'severity': 'medium',
            'description': 'Phishing domain',
            'tags': ['phishing']
        },
        {
            'value': 'a1b2c3d4e5f6789012345678901234567890abcd',
            'ioc_type': 'hash_sha1',
            'threat_type': 'malware',
            'severity': 'critical',
            'description': 'Malware file hash',
            'tags': ['malware', 'trojan']
        },
        {
            'value': 'user@malicious.com',
            'ioc_type': 'email',
            'threat_type': 'phishing',
            'severity': 'medium',
            'description': 'Phishing email address',
            'tags': ['phishing', 'email']
        }
    ]
    
    created_iocs = []
    for ioc_data in test_iocs:
        ioc = ioc_manager.create_ioc(ioc_data, feed, user)
        created_iocs.append(ioc)
        print(f"✓ Created IOC: {ioc.ioc_type.upper()} - {ioc.value}")
    
    print(f"\n📊 Created {len(created_iocs)} test IOCs")
    
    # Test IOC extraction from text
    test_text = """
    Suspicious activity detected from IP 10.0.0.5 and domain evil.example.org.
    The malware sample has hash 1234567890abcdef1234567890abcdef12345678.
    Contact suspicious@badactor.net for more information.
    Visit http://malicious-site.com/payload for details.
    """
    
    extracted_iocs = ioc_manager.extract_iocs_from_text(test_text)
    print(f"\n🔍 Extracted IOCs from text:")
    for ioc_type, values in extracted_iocs.items():
        print(f"  {ioc_type.upper()}: {values}")
    
    # Test IOC matching
    test_matches = [
        ('192.168.1.100', 'ip'),
        ('malicious.example.com', 'domain'),
        ('unknown.example.com', 'domain'),
    ]
    
    print(f"\n🎯 Testing IOC matches:")
    for value, ioc_type in test_matches:
        matches = ioc_manager.check_ioc_matches(value, ioc_type)
        if matches:
            print(f"  ⚠️  MATCH: {value} ({ioc_type}) - {len(matches)} matches found")
        else:
            print(f"  ✅ No match: {value} ({ioc_type})")
    
    # Test IOC search
    search_results = ioc_manager.search_iocs('malicious')
    print(f"\n🔎 Search results for 'malicious': {len(search_results)} IOCs found")
    
    # Create a threat actor
    actor = ThreatActor.objects.create(
        name='Test APT Group',
        actor_type='apt',
        description='Advanced persistent threat group for testing',
        country='Unknown',
        motivation='Espionage and data theft',
        capabilities=['Advanced malware', 'Zero-day exploits'],
        targets=['Government', 'Financial institutions']
    )
    print(f"✓ Created threat actor: {actor.name}")
    
    # Create a threat campaign
    campaign = ThreatCampaign.objects.create(
        name='Operation Test Storm',
        description='Test campaign for IOC management',
        threat_actor=actor,
        status='active',
        first_seen=timezone.now(),
        targets=['Test targets'],
        attack_patterns=['Spear phishing', 'Lateral movement']
    )
    print(f"✓ Created threat campaign: {campaign.name}")
    
    # Associate IOCs with campaign
    campaign.iocs.set(created_iocs)
    print(f"✓ Associated {len(created_iocs)} IOCs with campaign")
    
    # Create a threat hunt
    hunt = ThreatHunt.objects.create(
        name='Hunt for Test Threats',
        description='Hunting for test threat indicators',
        hypothesis='Test threats are present in network traffic',
        hunt_type='IOC-based',
        hunter=user,
        start_date=timezone.now(),
        data_sources=['Network logs', 'DNS logs'],
        search_queries=['SELECT * FROM logs WHERE ip = "192.168.1.100"']
    )
    print(f"✓ Created threat hunt: {hunt.name}")
    
    # Get IOC statistics
    stats = ioc_manager.get_ioc_statistics()
    print(f"\n📈 IOC Statistics:")
    print(f"  Total IOCs: {stats['total_iocs']}")
    print(f"  Active IOCs: {stats['active_iocs']}")
    print(f"  By Type: {stats['by_type']}")
    print(f"  By Severity: {stats['by_severity']}")
    print(f"  Recent Matches: {stats['recent_matches']}")
    
    print(f"\n🎉 IOC Management System test completed successfully!")
    
    # Display summary
    print(f"\n📋 Test Summary:")
    print(f"  - Threat Feeds: {ThreatFeed.objects.count()}")
    print(f"  - IOCs: {IndicatorOfCompromise.objects.count()}")
    print(f"  - Threat Actors: {ThreatActor.objects.count()}")
    print(f"  - Threat Campaigns: {ThreatCampaign.objects.count()}")
    print(f"  - Threat Hunts: {ThreatHunt.objects.count()}")
    print(f"  - Threat Matches: {ThreatMatch.objects.count()}")
    
    return True

if __name__ == '__main__':
    try:
        test_ioc_management()
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)