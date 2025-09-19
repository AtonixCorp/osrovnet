"""
Intrusion Detection and Prevention System (IDPS)
"""
import re
import time
import threading
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict, deque
from django.utils import timezone
from .models import (
    IntrusionDetectionRule, TrafficPattern, NetworkAlert, 
    NetworkTraffic, DiscoveredHost
)

logger = logging.getLogger('osrovnet.ids')

class IntrusionDetectionEngine:
    """
    Advanced Intrusion Detection and Prevention System
    """
    
    def __init__(self):
        self.running = False
        self.monitoring_thread = None
        self.traffic_buffer = deque(maxlen=10000)  # Keep last 10k packets
        self.pattern_cache = {}
        self.anomaly_baselines = {}
        
        # Traffic analysis windows
        self.analysis_windows = {
            'short': timedelta(minutes=5),
            'medium': timedelta(minutes=30),
            'long': timedelta(hours=2)
        }
        
        # Predefined attack patterns
        self.attack_signatures = {
            'port_scan': {
                'pattern': r'tcp.*SYN.*(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
                'threshold': 10,  # connections per minute
                'severity': 'medium'
            },
            'brute_force_ssh': {
                'pattern': r'ssh.*failed|authentication.*failed',
                'threshold': 5,  # failed attempts per minute
                'severity': 'high'
            },
            'ddos_syn_flood': {
                'pattern': r'tcp.*SYN',
                'threshold': 100,  # SYN packets per second
                'severity': 'critical'
            },
            'sql_injection': {
                'pattern': r'(?i)(union.*select|select.*from|insert.*into|drop.*table)',
                'threshold': 1,
                'severity': 'critical'
            },
            'xss_attempt': {
                'pattern': r'(?i)(<script|javascript:|onerror=|onload=)',
                'threshold': 1,
                'severity': 'high'
            }
        }
    
    def start_monitoring(self):
        """Start the intrusion detection monitoring"""
        if not self.running:
            self.running = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()
            logger.info("Intrusion Detection System started")
    
    def stop_monitoring(self):
        """Stop the intrusion detection monitoring"""
        self.running = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        logger.info("Intrusion Detection System stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop for intrusion detection"""
        while self.running:
            try:
                # Analyze recent traffic
                self._analyze_traffic_patterns()
                
                # Check for anomalies
                self._detect_anomalies()
                
                # Apply signature-based detection
                self._signature_based_detection()
                
                # Behavioral analysis
                self._behavioral_analysis()
                
                # Sleep for analysis interval
                time.sleep(30)  # Analyze every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in IDS monitoring loop: {str(e)}")
                time.sleep(60)  # Wait longer on error
    
    def analyze_packet(self, packet_data: Dict) -> List[Dict]:
        """
        Analyze a single packet for intrusion indicators
        
        Args:
            packet_data: Dictionary containing packet information
            
        Returns:
            List of detected threats/alerts
        """
        alerts = []
        
        # Add to traffic buffer
        self.traffic_buffer.append({
            'timestamp': timezone.now(),
            'data': packet_data
        })
        
        # Check against active rules
        active_rules = IntrusionDetectionRule.objects.filter(is_active=True)
        
        for rule in active_rules:
            if self._match_rule(packet_data, rule):
                alert = self._create_alert_from_rule(packet_data, rule)
                alerts.append(alert)
        
        # Check against built-in signatures
        for signature_name, signature in self.attack_signatures.items():
            if self._match_signature(packet_data, signature):
                alert = self._create_alert_from_signature(packet_data, signature_name, signature)
                alerts.append(alert)
        
        return alerts
    
    def _analyze_traffic_patterns(self):
        """Analyze traffic patterns for suspicious activity"""
        try:
            # Get recent traffic from database
            recent_traffic = NetworkTraffic.objects.filter(
                timestamp__gte=timezone.now() - self.analysis_windows['short']
            )
            
            # Group by source IP for analysis
            ip_patterns = defaultdict(list)
            for traffic in recent_traffic:
                ip_patterns[traffic.source_ip].append(traffic)
            
            # Analyze each IP's traffic pattern
            for source_ip, traffic_list in ip_patterns.items():
                self._analyze_ip_pattern(source_ip, traffic_list)
        
        except Exception as e:
            logger.error(f"Error analyzing traffic patterns: {str(e)}")
    
    def _analyze_ip_pattern(self, source_ip: str, traffic_list: List):
        """Analyze traffic patterns for a specific IP"""
        # Port scan detection
        unique_ports = set()
        unique_destinations = set()
        
        for traffic in traffic_list:
            unique_ports.add(traffic.destination_port)
            unique_destinations.add(traffic.destination_ip)
        
        # Check for port scanning
        if len(unique_ports) > 20 and len(traffic_list) > 50:
            self._create_pattern_alert(
                'port_scan',
                source_ip,
                f"Potential port scan detected: {len(unique_ports)} ports on {len(unique_destinations)} hosts",
                'medium',
                {
                    'unique_ports': len(unique_ports),
                    'unique_destinations': len(unique_destinations),
                    'total_packets': len(traffic_list)
                }
            )
        
        # Check for DDoS patterns
        if len(traffic_list) > 200:  # High packet rate
            self._create_pattern_alert(
                'ddos',
                source_ip,
                f"Potential DDoS attack detected: {len(traffic_list)} packets in 5 minutes",
                'critical',
                {
                    'packet_rate': len(traffic_list) / 5,  # packets per minute
                    'total_packets': len(traffic_list)
                }
            )
    
    def _detect_anomalies(self):
        """Detect traffic anomalies using statistical analysis"""
        try:
            current_time = timezone.now()
            
            # Analyze traffic volume anomalies
            self._detect_volume_anomalies(current_time)
            
            # Analyze protocol distribution anomalies
            self._detect_protocol_anomalies(current_time)
            
            # Analyze timing anomalies
            self._detect_timing_anomalies(current_time)
        
        except Exception as e:
            logger.error(f"Error in anomaly detection: {str(e)}")
    
    def _detect_volume_anomalies(self, current_time: datetime):
        """Detect anomalies in traffic volume"""
        # Get traffic counts for different time windows
        short_window = NetworkTraffic.objects.filter(
            timestamp__gte=current_time - self.analysis_windows['short']
        ).count()
        
        medium_window = NetworkTraffic.objects.filter(
            timestamp__gte=current_time - self.analysis_windows['medium']
        ).count()
        
        # Calculate rates
        short_rate = short_window / 5  # packets per minute
        medium_rate = medium_window / 30  # packets per minute
        
        # Check for significant deviation
        if short_rate > medium_rate * 3:  # 3x increase
            self._create_pattern_alert(
                'anomaly',
                None,
                f"Traffic volume anomaly detected: {short_rate:.1f} vs {medium_rate:.1f} pkt/min",
                'medium',
                {
                    'current_rate': short_rate,
                    'baseline_rate': medium_rate,
                    'deviation_factor': short_rate / medium_rate if medium_rate > 0 else 0
                }
            )
    
    def _detect_protocol_anomalies(self, current_time: datetime):
        """Detect anomalies in protocol distribution"""
        # Get protocol distribution for recent traffic
        recent_protocols = NetworkTraffic.objects.filter(
            timestamp__gte=current_time - self.analysis_windows['short']
        ).values('protocol').distinct()
        
        # Check for unusual protocols
        common_protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS']
        for proto_data in recent_protocols:
            protocol = proto_data['protocol']
            if protocol not in common_protocols:
                count = NetworkTraffic.objects.filter(
                    timestamp__gte=current_time - self.analysis_windows['short'],
                    protocol=protocol
                ).count()
                
                if count > 10:  # Unusual protocol with significant traffic
                    self._create_pattern_alert(
                        'anomaly',
                        None,
                        f"Unusual protocol activity: {protocol} ({count} packets)",
                        'low',
                        {
                            'protocol': protocol,
                            'packet_count': count
                        }
                    )
    
    def _signature_based_detection(self):
        """Apply signature-based detection rules"""
        try:
            # Get recent traffic for signature matching
            recent_traffic = NetworkTraffic.objects.filter(
                timestamp__gte=timezone.now() - timedelta(minutes=1)
            )
            
            for traffic in recent_traffic:
                # Create packet-like data structure
                packet_data = {
                    'source_ip': traffic.source_ip,
                    'destination_ip': traffic.destination_ip,
                    'source_port': traffic.source_port,
                    'destination_port': traffic.destination_port,
                    'protocol': traffic.protocol,
                    'payload': traffic.payload_snippet,
                    'flags': traffic.flags
                }
                
                # Check against signatures
                for signature_name, signature in self.attack_signatures.items():
                    if self._match_signature(packet_data, signature):
                        self._create_alert_from_signature(packet_data, signature_name, signature)
        
        except Exception as e:
            logger.error(f"Error in signature-based detection: {str(e)}")
    
    def _behavioral_analysis(self):
        """Perform behavioral analysis for advanced threat detection"""
        try:
            # Analyze host behavior patterns
            hosts = DiscoveredHost.objects.filter(
                last_seen__gte=timezone.now() - timedelta(hours=1)
            )
            
            for host in hosts:
                self._analyze_host_behavior(host)
        
        except Exception as e:
            logger.error(f"Error in behavioral analysis: {str(e)}")
    
    def _analyze_host_behavior(self, host):
        """Analyze behavior patterns for a specific host"""
        # Get traffic patterns for this host
        outbound_traffic = NetworkTraffic.objects.filter(
            source_ip=host.ip_address,
            timestamp__gte=timezone.now() - timedelta(hours=1)
        )
        
        inbound_traffic = NetworkTraffic.objects.filter(
            destination_ip=host.ip_address,
            timestamp__gte=timezone.now() - timedelta(hours=1)
        )
        
        # Check for data exfiltration patterns
        outbound_size = sum(t.packet_size for t in outbound_traffic)
        inbound_size = sum(t.packet_size for t in inbound_traffic)
        
        if outbound_size > inbound_size * 10:  # Much more outbound than inbound
            self._create_pattern_alert(
                'data_exfiltration',
                host.ip_address,
                f"Potential data exfiltration: {outbound_size} bytes out vs {inbound_size} bytes in",
                'high',
                {
                    'outbound_bytes': outbound_size,
                    'inbound_bytes': inbound_size,
                    'ratio': outbound_size / inbound_size if inbound_size > 0 else 0
                }
            )
    
    def _match_rule(self, packet_data: Dict, rule: IntrusionDetectionRule) -> bool:
        """Check if packet matches an IDS rule"""
        try:
            pattern = rule.pattern
            
            # Create searchable text from packet data
            search_text = json.dumps(packet_data).lower()
            
            # Apply pattern matching based on rule type
            if rule.rule_type == 'signature':
                return bool(re.search(pattern, search_text, re.IGNORECASE))
            elif rule.rule_type == 'heuristic':
                return self._apply_heuristic_rule(packet_data, pattern)
            
            return False
        
        except Exception as e:
            logger.error(f"Error matching rule {rule.name}: {str(e)}")
            return False
    
    def _match_signature(self, packet_data: Dict, signature: Dict) -> bool:
        """Check if packet matches a signature"""
        try:
            pattern = signature['pattern']
            
            # Create searchable text from packet data
            search_text = json.dumps(packet_data).lower()
            
            return bool(re.search(pattern, search_text, re.IGNORECASE))
        
        except Exception as e:
            logger.error(f"Error matching signature: {str(e)}")
            return False
    
    def _apply_heuristic_rule(self, packet_data: Dict, pattern: str) -> bool:
        """Apply heuristic-based rule matching"""
        # Implement custom heuristic logic based on pattern
        # This could include statistical analysis, machine learning, etc.
        return False
    
    def _create_alert_from_rule(self, packet_data: Dict, rule: IntrusionDetectionRule) -> Dict:
        """Create alert from IDS rule match"""
        alert_data = {
            'alert_type': 'intrusion_attempt',
            'severity': rule.severity,
            'title': f"IDS Rule Triggered: {rule.name}",
            'description': f"Rule '{rule.name}' triggered by traffic from {packet_data.get('source_ip')}",
            'source_ip': packet_data.get('source_ip'),
            'destination_ip': packet_data.get('destination_ip'),
            'metadata': {
                'rule_id': rule.id,
                'rule_type': rule.rule_type,
                'packet_data': packet_data
            }
        }
        
        # Create alert in database
        NetworkAlert.objects.create(**alert_data)
        
        return alert_data
    
    def _create_alert_from_signature(self, packet_data: Dict, signature_name: str, signature: Dict) -> Dict:
        """Create alert from signature match"""
        alert_data = {
            'alert_type': 'security',
            'severity': signature['severity'],
            'title': f"Attack Signature Detected: {signature_name.replace('_', ' ').title()}",
            'description': f"Attack pattern '{signature_name}' detected from {packet_data.get('source_ip')}",
            'source_ip': packet_data.get('source_ip'),
            'destination_ip': packet_data.get('destination_ip'),
            'metadata': {
                'signature_name': signature_name,
                'pattern': signature['pattern'],
                'packet_data': packet_data
            }
        }
        
        # Create alert in database
        NetworkAlert.objects.create(**alert_data)
        
        return alert_data
    
    def _create_pattern_alert(self, pattern_type: str, source_ip: Optional[str], 
                            description: str, severity: str, metadata: Dict):
        """Create alert for detected traffic pattern"""
        # Check if similar alert exists recently (avoid spam)
        recent_similar = NetworkAlert.objects.filter(
            alert_type='anomaly',
            source_ip=source_ip,
            created_at__gte=timezone.now() - timedelta(minutes=10)
        ).exists()
        
        if not recent_similar:
            NetworkAlert.objects.create(
                alert_type='anomaly',
                severity=severity,
                title=f"Traffic Pattern Alert: {pattern_type.replace('_', ' ').title()}",
                description=description,
                source_ip=source_ip,
                metadata=metadata
            )
    
    def get_detection_statistics(self) -> Dict:
        """Get intrusion detection statistics"""
        current_time = timezone.now()
        
        # Count alerts by type and severity in last 24 hours
        recent_alerts = NetworkAlert.objects.filter(
            created_at__gte=current_time - timedelta(hours=24)
        )
        
        stats = {
            'total_alerts': recent_alerts.count(),
            'alerts_by_type': {},
            'alerts_by_severity': {},
            'top_source_ips': [],
            'detection_rate': 0.0,
            'false_positive_rate': 0.0
        }
        
        # Group by type
        for alert_type in ['security', 'anomaly', 'intrusion_attempt']:
            count = recent_alerts.filter(alert_type=alert_type).count()
            stats['alerts_by_type'][alert_type] = count
        
        # Group by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            count = recent_alerts.filter(severity=severity).count()
            stats['alerts_by_severity'][severity] = count
        
        # Top source IPs
        from django.db.models import Count
        top_ips = recent_alerts.exclude(source_ip__isnull=True).values(
            'source_ip'
        ).annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        stats['top_source_ips'] = list(top_ips)
        
        return stats

# Singleton instance
intrusion_detector = IntrusionDetectionEngine()