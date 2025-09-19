# IOC Management System - Complete Integration Guide

## 🎯 Overview

The IOC (Indicators of Compromise) Management System is now fully integrated into your OSROVNet project. This system provides comprehensive threat intelligence capabilities including IOC creation, management, enrichment, and automated threat detection.

## ✅ What's Been Added

### 1. **Complete IOC Database Models**
- `ThreatFeed` - External threat intelligence sources
- `IndicatorOfCompromise` - IOC storage with validation and enrichment
- `ThreatActor` - Threat actor/group tracking
- `ThreatCampaign` - Campaign and operation tracking
- `ThreatMatch` - IOC matches against network activity
- `ThreatHunt` - Threat hunting campaigns
- `ThreatIntelligenceReport` - Intelligence reports
- `ThreatResponsePlaybook` - Automated response workflows

### 2. **IOC Management Service**
- **IOC Validation**: Automatic format validation for IPs, domains, URLs, hashes, emails
- **IOC Normalization**: Consistent formatting and storage
- **Bulk Import**: Import IOCs from multiple threat feeds
- **Text Extraction**: Extract IOCs from unstructured text using regex
- **IOC Matching**: Check network activity against known IOCs
- **Enrichment**: External source integration (VirusTotal, OTX, Abuse.ch)
- **Search & Filtering**: Advanced IOC search capabilities

### 3. **Comprehensive API Endpoints**

#### Threat Intelligence APIs:
```bash
# IOC Management
GET    /api/threat-intel/iocs/                    # List IOCs
POST   /api/threat-intel/iocs/                    # Create IOC
POST   /api/threat-intel/iocs/bulk_import/        # Bulk import IOCs
POST   /api/threat-intel/iocs/search/             # Advanced search
POST   /api/threat-intel/iocs/extract_from_text/  # Extract IOCs from text
POST   /api/threat-intel/iocs/{id}/enrich/        # Enrich specific IOC

# Threat Feeds
GET    /api/threat-intel/threat-feeds/            # List feeds
POST   /api/threat-intel/threat-feeds/            # Create feed
POST   /api/threat-intel/threat-feeds/{id}/sync_feed/  # Sync feed

# Threat Matches
GET    /api/threat-intel/threat-matches/          # List matches
POST   /api/threat-intel/threat-matches/check_matches/  # Check for matches

# Threat Actors & Campaigns
GET    /api/threat-intel/threat-actors/           # List threat actors
GET    /api/threat-intel/threat-campaigns/        # List campaigns

# Threat Hunting
GET    /api/threat-intel/threat-hunts/            # List hunts
POST   /api/threat-intel/threat-hunts/            # Create hunt
POST   /api/threat-intel/threat-hunts/{id}/start_hunt/    # Start hunt
POST   /api/threat-intel/threat-hunts/{id}/complete_hunt/ # Complete hunt

# Dashboard & Management
GET    /api/threat-intel/dashboard/               # Threat intel dashboard
POST   /api/threat-intel/ioc-management/         # IOC management operations
```

## 🚀 How to Use the IOC System

### 1. **Create a Threat Feed**
```bash
curl -X POST http://localhost:8000/api/threat-intel/threat-feeds/ \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Threat Feed",
    "feed_type": "custom",
    "description": "Custom threat intelligence feed",
    "confidence_level": 75
  }'
```

### 2. **Add IOCs**
```bash
curl -X POST http://localhost:8000/api/threat-intel/iocs/ \
  -H "Content-Type: application/json" \
  -d '{
    "value": "192.168.1.100",
    "ioc_type": "ip",
    "threat_type": "malware",
    "severity": "high",
    "description": "Malicious C2 server",
    "tags": ["malware", "c2"],
    "source_feed": 1
  }'
```

### 3. **Bulk Import IOCs**
```bash
curl -X POST http://localhost:8000/api/threat-intel/iocs/bulk_import/ \
  -H "Content-Type: application/json" \
  -d '{
    "source_feed_id": 1,
    "iocs_data": [
      {
        "value": "evil.com",
        "ioc_type": "domain",
        "threat_type": "phishing",
        "severity": "medium"
      },
      {
        "value": "1234567890abcdef1234567890abcdef12345678",
        "ioc_type": "hash_sha1",
        "threat_type": "malware",
        "severity": "critical"
      }
    ]
  }'
```

### 4. **Extract IOCs from Text**
```bash
curl -X POST http://localhost:8000/api/threat-intel/iocs/extract_from_text/ \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Suspicious traffic from IP 10.0.0.5 to domain evil.example.com",
    "create_iocs": true,
    "source_feed_id": 1
  }'
```

### 5. **Check for IOC Matches**
```bash
curl -X POST http://localhost:8000/api/threat-intel/threat-matches/check_matches/ \
  -H "Content-Type: application/json" \
  -d '{
    "value": "192.168.1.100",
    "ioc_type": "ip",
    "source_ip": "10.0.0.1"
  }'
```

### 6. **Search IOCs**
```bash
curl -X POST http://localhost:8000/api/threat-intel/iocs/search/ \
  -H "Content-Type: application/json" \
  -d '{
    "query": "malicious",
    "ioc_type": "domain",
    "severity": "high"
  }'
```

## 🔧 Python Integration Examples

### 1. **Using IOC Manager Service**
```python
from threat_intelligence.ioc_service import ioc_manager
from threat_intelligence.models import ThreatFeed

# Create IOC
ioc_data = {
    'value': '192.168.1.100',
    'ioc_type': 'ip',
    'threat_type': 'malware',
    'severity': 'high',
    'description': 'C2 server'
}
feed = ThreatFeed.objects.first()
ioc = ioc_manager.create_ioc(ioc_data, feed, user)

# Check for matches
matches = ioc_manager.check_ioc_matches('192.168.1.100', 'ip')

# Extract IOCs from text
extracted = ioc_manager.extract_iocs_from_text(suspicious_text)
```

### 2. **Integration with Network Monitoring**
```python
# In your network monitoring code
from threat_intelligence.ioc_service import ioc_manager

def check_network_activity(ip_address, domain=None):
    """Check network activity against IOCs"""
    threats_found = []
    
    # Check IP
    matches = ioc_manager.check_ioc_matches(ip_address, 'ip')
    threats_found.extend(matches)
    
    # Check domain if available
    if domain:
        domain_matches = ioc_manager.check_ioc_matches(domain, 'domain')
        threats_found.extend(domain_matches)
    
    return threats_found
```

### 3. **Automated IOC Processing**
```python
def process_threat_intelligence_feed(feed_url, feed_id):
    """Process external threat feed"""
    import requests
    
    # Fetch feed data
    response = requests.get(feed_url)
    feed_data = response.json()
    
    # Process IOCs
    iocs_data = []
    for item in feed_data:
        ioc_data = {
            'value': item['indicator'],
            'ioc_type': item['type'],
            'threat_type': item.get('threat_type', 'suspicious'),
            'severity': item.get('severity', 'medium'),
            'description': item.get('description', ''),
            'confidence': item.get('confidence', 50)
        }
        iocs_data.append(ioc_data)
    
    # Bulk import
    feed = ThreatFeed.objects.get(id=feed_id)
    results = ioc_manager.bulk_import_iocs(iocs_data, feed)
    
    return results
```

## 📊 Dashboard Integration

### Get Threat Intelligence Dashboard Data:
```bash
curl http://localhost:8000/api/threat-intel/dashboard/
```

Response includes:
- IOC statistics by type and severity
- Recent threat matches
- Active threat actors and campaigns
- Threat feed status
- Active threat hunts

## 🔍 IOC Types Supported

- **IP Addresses**: IPv4 and IPv6 addresses
- **Domains**: Domain names and subdomains
- **URLs**: Complete URLs including paths
- **File Hashes**: MD5, SHA1, SHA256
- **Email Addresses**: Email addresses
- **File Paths**: File system paths
- **Registry Keys**: Windows registry keys
- **User Agents**: Browser user agent strings
- **Certificates**: SSL/TLS certificates
- **Mutex**: Windows mutex objects
- **YARA Rules**: YARA detection rules

## 🛡️ Security Features

### 1. **Traffic Light Protocol (TLP)**
- Supports TLP marking for information sharing
- Controls data distribution and visibility

### 2. **Confidence Scoring**
- 0-100 confidence levels for IOCs
- Weighted matching based on confidence

### 3. **IOC Expiration**
- Automatic expiration of old IOCs
- Configurable retention policies

### 4. **Access Control**
- User-based IOC creation and management
- Role-based access to sensitive intelligence

## 🔄 Integration with Network Security

The IOC system automatically integrates with your existing network security components:

### 1. **Network Scanning Integration**
```python
# In network_security/services.py
from threat_intelligence.ioc_service import ioc_manager

def enhanced_scan_processing(scan_results):
    """Enhanced scan processing with IOC checking"""
    for host_ip, host_data in scan_results.items():
        # Check host IP against IOCs
        matches = ioc_manager.check_ioc_matches(host_ip, 'ip')
        if matches:
            # Create security alert
            create_security_alert(host_ip, matches)
```

### 2. **IDS Integration**
```python
# In network_security/ids_service.py
def enhanced_intrusion_detection(packet_data):
    """Enhanced IDS with IOC matching"""
    # Extract indicators from packet
    source_ip = packet_data.get('source_ip')
    
    # Check against IOCs
    matches = ioc_manager.check_ioc_matches(source_ip, 'ip')
    
    if matches:
        return create_threat_alert(matches, packet_data)
```

## 📈 Performance Considerations

### 1. **Database Indexing**
- Optimized indexes on IOC values and types
- Efficient querying for real-time matching

### 2. **Caching**
- IOC lookup caching for performance
- Configurable cache TTL

### 3. **Bulk Operations**
- Efficient bulk import and processing
- Transaction optimization

## 🧪 Testing

Run the comprehensive test suite:
```bash
cd /home/atonixdev/atonixcorpvm/osrovnet
source .venv/bin/activate
python test_ioc_management.py
```

This tests:
- IOC creation and validation
- Text extraction capabilities
- IOC matching functionality
- Threat actor and campaign management
- Search and filtering

## 🔧 Configuration

### 1. **Environment Variables**
```bash
# Add to your .env file
VIRUSTOTAL_API_KEY=your_vt_api_key
OTX_API_KEY=your_otx_api_key
THREAT_FEED_UPDATE_INTERVAL=3600
IOC_RETENTION_DAYS=90
```

### 2. **Django Settings**
```python
# In settings.py
THREAT_INTELLIGENCE = {
    'IOC_RETENTION_DAYS': 90,
    'AUTO_ENRICH_IOCS': True,
    'MAX_BULK_IMPORT_SIZE': 10000,
    'ENABLE_EXTERNAL_ENRICHMENT': True
}
```

## 🚀 Next Steps

1. **External Feed Integration**: Connect to real threat feeds (MISP, OTX, etc.)
2. **Machine Learning**: Add ML-based IOC scoring and classification
3. **Visualization**: Create threat landscape visualizations
4. **Automated Response**: Implement SOAR-like automated response workflows
5. **Report Generation**: Add threat intelligence reporting capabilities

## ✅ System Status

✅ **IOC Database Models** - Complete
✅ **IOC Management Service** - Complete  
✅ **REST API Endpoints** - Complete
✅ **Database Migrations** - Applied
✅ **Input Validation** - Complete
✅ **Search & Filtering** - Complete
✅ **Bulk Operations** - Complete
✅ **Testing Suite** - Complete
✅ **Documentation** - Complete

Your IOC Management System is now fully operational and ready for production use! 🎉