import nmap
import ipaddress
import socket
import threading
import time
import logging
import json
import re
import subprocess
import requests
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from .models import NetworkScan, DiscoveredHost, DiscoveredPort, Vulnerability, NetworkAlert

logger = logging.getLogger('osrovnet.network_security')

class NetworkScanner:
    """
    Advanced network scanner using nmap and custom scanning techniques
    Supports multiple scan types, vulnerability detection, and service fingerprinting
    """
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.vulnerability_db = {}
        self._load_vulnerability_signatures()
        
        # Advanced scan configurations
        self.scan_techniques = {
            'tcp_syn': '-sS',           # TCP SYN scan (stealth)
            'tcp_connect': '-sT',       # TCP connect scan
            'udp': '-sU',              # UDP scan
            'tcp_ack': '-sA',          # TCP ACK scan
            'tcp_window': '-sW',       # TCP Window scan
            'tcp_maimon': '-sM',       # TCP Maimon scan
            'tcp_null': '-sN',         # TCP Null scan
            'tcp_fin': '-sF',          # TCP FIN scan
            'tcp_xmas': '-sX',         # TCP Xmas scan
            'ping_sweep': '-sn',       # Ping sweep (no port scan)
            'comprehensive': '-sS -sV -O -A --script=vuln',  # Comprehensive scan
        }
        
    def _load_vulnerability_signatures(self):
        """Load vulnerability signatures and patterns"""
        self.vulnerability_db = {
            # Common vulnerabilities and their patterns
            'CVE-2017-0144': {
                'name': 'EternalBlue SMB Vulnerability',
                'services': ['microsoft-ds', 'netbios-ssn'],
                'ports': [139, 445],
                'severity': 'critical',
                'cvss': 9.3,
                'pattern': r'SMBv1.*enabled'
            },
            'CVE-2014-6271': {
                'name': 'Shellshock Bash Vulnerability',
                'services': ['http', 'https'],
                'ports': [80, 443],
                'severity': 'critical',
                'cvss': 9.8,
                'pattern': r'bash.*CGI'
            },
            'CVE-2017-5638': {
                'name': 'Apache Struts2 Remote Code Execution',
                'services': ['http', 'https'],
                'ports': [80, 443, 8080],
                'severity': 'critical',
                'cvss': 9.8,
                'pattern': r'Struts.*2\.[0-5]'
            },
            'anonymous_ftp': {
                'name': 'Anonymous FTP Access',
                'services': ['ftp'],
                'ports': [21],
                'severity': 'medium',
                'cvss': 5.0,
                'pattern': r'Anonymous FTP login allowed'
            },
            'weak_ssl': {
                'name': 'Weak SSL/TLS Configuration',
                'services': ['https', 'ssl'],
                'ports': [443, 993, 995],
                'severity': 'medium',
                'cvss': 4.3,
                'pattern': r'SSL.*weak|TLS.*1\.[01]'
            }
        }
    
    def _build_scan_arguments(self, scan_type: str, ports: str, 
                             enable_os_detection: bool = False,
                             enable_service_detection: bool = True,
                             enable_vulnerability_scan: bool = True) -> str:
        """Build nmap scan arguments based on options"""
        args = []
        
        # Base scan technique
        if scan_type in self.scan_techniques:
            if scan_type == 'comprehensive':
                args.append(self.scan_techniques[scan_type])
            else:
                args.append(self.scan_techniques[scan_type])
                args.append(f'-p {ports}')
        else:
            # Default quick scan
            args.extend(['-sS', f'-p {ports}', '--min-rate=1000'])
        
        # Add detection options
        if enable_service_detection and scan_type != 'comprehensive':
            args.append('-sV')
        
        if enable_os_detection and scan_type != 'comprehensive':
            args.append('-O')
        
        if enable_vulnerability_scan and scan_type != 'comprehensive':
            args.append('--script=vuln,discovery')
        
        # Performance tuning
        args.extend(['-T4', '--max-retries=1'])
        
        return ' '.join(args)
    
    def scan_target(self, target: str, scan_type: str = 'quick', ports: str = '1-1000', 
                   enable_os_detection: bool = False, enable_service_detection: bool = True,
                   enable_vulnerability_scan: bool = True) -> Dict:
        """
        Perform advanced network scan with multiple techniques
        
        Args:
            target: Target IP, range, or hostname
            scan_type: Type of scan to perform
            ports: Port range or specific ports
            enable_os_detection: Enable OS fingerprinting
            enable_service_detection: Enable service version detection
            enable_vulnerability_scan: Enable vulnerability scanning
        """
        try:
            logger.info(f"Starting advanced scan: {scan_type} on {target}")
            
            # Build scan arguments based on type and options
            scan_args = self._build_scan_arguments(
                scan_type, ports, enable_os_detection, 
                enable_service_detection, enable_vulnerability_scan
            )
            
            # Execute the scan
            logger.info(f"Executing scan with arguments: {scan_args}")
            results = self.nm.scan(hosts=target, arguments=scan_args)
            
            # Enhanced results processing
            enhanced_results = self._enhance_scan_results(results)
            
            logger.info(f"Scan completed for {target}. Hosts found: {len(enhanced_results.get('scan', {}))}")
            return enhanced_results
            
        except Exception as e:
            logger.error(f"Advanced scan failed for {target}: {str(e)}")
            return {'scan': {}, 'error': str(e)}
    
    def _enhance_scan_results(self, results: Dict) -> Dict:
        """Enhance scan results with additional analysis"""
        enhanced = results.copy()
        
        for host_ip, host_data in results.get('scan', {}).items():
            # Add vulnerability assessment
            enhanced['scan'][host_ip]['vulnerabilities'] = self._assess_vulnerabilities(host_ip, host_data)
            
            # Add risk assessment
            enhanced['scan'][host_ip]['risk_score'] = self._calculate_risk_score(host_data)
            
            # Add service fingerprinting
            enhanced['scan'][host_ip]['fingerprints'] = self._analyze_service_fingerprints(host_data)
            
        return enhanced
    
    def _assess_vulnerabilities(self, host_ip: str, host_data: Dict) -> List[Dict]:
        """Assess vulnerabilities based on discovered services and versions"""
        vulnerabilities = []
        
        # Check TCP ports
        for port_num, port_data in host_data.get('tcp', {}).items():
            service = port_data.get('name', '')
            version = port_data.get('version', '')
            product = port_data.get('product', '')
            
            # Check against vulnerability database
            for vuln_id, vuln_info in self.vulnerability_db.items():
                if self._matches_vulnerability(port_num, service, version, product, vuln_info):
                    vulnerabilities.append({
                        'id': vuln_id,
                        'name': vuln_info['name'],
                        'severity': vuln_info['severity'],
                        'cvss': vuln_info['cvss'],
                        'port': port_num,
                        'service': service,
                        'description': f"Vulnerability found in {service} on port {port_num}"
                    })
        
        # Check UDP ports
        for port_num, port_data in host_data.get('udp', {}).items():
            service = port_data.get('name', '')
            version = port_data.get('version', '')
            
            for vuln_id, vuln_info in self.vulnerability_db.items():
                if self._matches_vulnerability(port_num, service, version, '', vuln_info):
                    vulnerabilities.append({
                        'id': vuln_id,
                        'name': vuln_info['name'],
                        'severity': vuln_info['severity'],
                        'cvss': vuln_info['cvss'],
                        'port': port_num,
                        'service': service,
                        'description': f"Vulnerability found in {service} on UDP port {port_num}"
                    })
        
        return vulnerabilities
    
    def _matches_vulnerability(self, port: int, service: str, version: str, 
                              product: str, vuln_info: Dict) -> bool:
        """Check if a service matches a vulnerability pattern"""
        # Check port match
        if port in vuln_info.get('ports', []):
            return True
        
        # Check service match
        if service.lower() in [s.lower() for s in vuln_info.get('services', [])]:
            # If there's a pattern, check it against version/product info
            pattern = vuln_info.get('pattern', '')
            if pattern:
                text_to_check = f"{service} {version} {product}".lower()
                return bool(re.search(pattern.lower(), text_to_check))
            return True
        
        return False
    
    def _calculate_risk_score(self, host_data: Dict) -> float:
        """Calculate risk score for a host based on open ports and services"""
        risk_score = 0.0
        
        # Base score for being alive
        if host_data.get('status', {}).get('state') == 'up':
            risk_score += 1.0
        
        # Add points for open ports
        tcp_ports = len(host_data.get('tcp', {}))
        udp_ports = len(host_data.get('udp', {}))
        risk_score += (tcp_ports * 0.5) + (udp_ports * 0.3)
        
        # Add points for high-risk services
        high_risk_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995]
        for port in high_risk_ports:
            if str(port) in host_data.get('tcp', {}):
                risk_score += 2.0
        
        # Add points for vulnerabilities
        vulnerabilities = host_data.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            severity_multiplier = {
                'critical': 5.0,
                'high': 3.0,
                'medium': 2.0,
                'low': 1.0
            }
            risk_score += severity_multiplier.get(vuln.get('severity', 'low'), 1.0)
        
        return min(risk_score, 10.0)  # Cap at 10.0
    
    def _analyze_service_fingerprints(self, host_data: Dict) -> Dict:
        """Analyze service fingerprints for additional information"""
        fingerprints = {
            'os_fingerprint': self._extract_os_fingerprint(host_data),
            'service_versions': self._extract_service_versions(host_data),
            'banner_analysis': self._analyze_banners(host_data)
        }
        return fingerprints
    
    def _extract_os_fingerprint(self, host_data: Dict) -> Dict:
        """Extract OS fingerprint information"""
        os_info = {}
        
        # Check for OS match from nmap
        if 'osmatch' in host_data:
            matches = host_data['osmatch']
            if matches:
                best_match = max(matches, key=lambda x: int(x.get('accuracy', 0)))
                os_info = {
                    'name': best_match.get('name', ''),
                    'accuracy': best_match.get('accuracy', ''),
                    'family': best_match.get('osclass', [{}])[0].get('osfamily', '') if best_match.get('osclass') else '',
                    'version': best_match.get('osclass', [{}])[0].get('osgen', '') if best_match.get('osclass') else ''
                }
        
        return os_info
    
    def _extract_service_versions(self, host_data: Dict) -> Dict:
        """Extract detailed service version information"""
        services = {}
        
        for port_num, port_data in host_data.get('tcp', {}).items():
            service_name = port_data.get('name', '')
            if service_name:
                services[f"tcp/{port_num}"] = {
                    'service': service_name,
                    'product': port_data.get('product', ''),
                    'version': port_data.get('version', ''),
                    'extrainfo': port_data.get('extrainfo', ''),
                    'cpe': port_data.get('cpe', '')
                }
        
        for port_num, port_data in host_data.get('udp', {}).items():
            service_name = port_data.get('name', '')
            if service_name:
                services[f"udp/{port_num}"] = {
                    'service': service_name,
                    'product': port_data.get('product', ''),
                    'version': port_data.get('version', ''),
                    'extrainfo': port_data.get('extrainfo', ''),
                    'cpe': port_data.get('cpe', '')
                }
        
        return services
    
    def _analyze_banners(self, host_data: Dict) -> Dict:
        """Analyze service banners for additional information"""
        banners = {}
        
        for port_num, port_data in host_data.get('tcp', {}).items():
            # Extract banner information from script results
            scripts = port_data.get('script', {})
            banner_info = []
            
            for script_name, script_output in scripts.items():
                if 'banner' in script_name.lower() or 'version' in script_name.lower():
                    banner_info.append({
                        'script': script_name,
                        'output': script_output[:200]  # Limit output length
                    })
            
            if banner_info:
                banners[f"tcp/{port_num}"] = banner_info
        
        return banners
        self.is_scanning = False
        self.scan_threads = {}
        
    def validate_target(self, target: str) -> bool:
        """Validate if target is a valid IP address or range"""
        try:
            # Try parsing as network
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            try:
                # Try parsing as single IP
                ipaddress.ip_address(target)
                return True
            except ValueError:
                # Try resolving hostname
                try:
                    socket.gethostbyname(target)
                    return True
                except socket.gaierror:
                    return False
    
    def perform_scan(self, scan_id: int) -> Dict[str, Any]:
        """
        Perform network scan based on scan configuration
        """
        try:
            scan = NetworkScan.objects.get(id=scan_id)
            scan.status = 'running'
            scan.save()
            
            logger.info(f"Starting scan {scan_id} for target {scan.target.target}")
            
            # Validate target
            if not self.validate_target(scan.target.target):
                scan.status = 'failed'
                scan.error_message = "Invalid target specified"
                scan.save()
                return {'success': False, 'error': 'Invalid target'}
            
            # Determine scan arguments based on scan type
            scan_args = self._get_scan_arguments(scan.target.scan_type, scan.target.ports)
            
            # Perform the scan
            scan_results = self.nm.scan(
                hosts=scan.target.target,
                arguments=scan_args
            )
            
            # Process scan results
            results = self._process_scan_results(scan, scan_results)
            
            # Update scan record
            scan.hosts_discovered = results['hosts_discovered']
            scan.ports_scanned = results['ports_scanned']
            scan.vulnerabilities_found = results['vulnerabilities_found']
            scan.scan_output = scan_results
            scan.mark_completed()
            
            logger.info(f"Completed scan {scan_id}: {results['hosts_discovered']} hosts, {results['ports_scanned']} ports")
            
            return {'success': True, 'results': results}
            
        except NetworkScan.DoesNotExist:
            logger.error(f"Scan {scan_id} not found")
            return {'success': False, 'error': 'Scan not found'}
        except Exception as e:
            logger.error(f"Error performing scan {scan_id}: {str(e)}")
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.save()
            return {'success': False, 'error': str(e)}
    
    def _get_scan_arguments(self, scan_type: str, ports: str) -> str:
        """Generate nmap arguments based on scan type"""
        base_args = "-sV -O --version-intensity 5"
        
        scan_configs = {
            'ping': "-sn",
            'tcp': f"-sS -p {ports}",
            'udp': f"-sU -p {ports}",
            'syn': f"-sS -p {ports}",
            'comprehensive': f"-sS -sU -sV -O -A --script vuln -p {ports}"
        }
        
        return scan_configs.get(scan_type, f"-sS -p {ports}")
    
    def _process_scan_results(self, scan: NetworkScan, results: Dict) -> Dict[str, int]:
        """Process and store scan results in database"""
        hosts_discovered = 0
        ports_scanned = 0
        vulnerabilities_found = 0
        
        for host_ip in results['scan']:
            host_data = results['scan'][host_ip]
            
            if host_data['status']['state'] == 'up':
                hosts_discovered += 1
                
                # Create or update discovered host
                host, created = DiscoveredHost.objects.get_or_create(
                    scan=scan,
                    ip_address=host_ip,
                    defaults={
                        'hostname': host_data.get('hostnames', [{}])[0].get('name', ''),
                        'mac_address': self._extract_mac_address(host_data),
                        'state': host_data['status']['state'],
                        'os_detection': self._extract_os_info(host_data),
                        'response_time': self._extract_response_time(host_data)
                    }
                )
                
                # Process discovered ports
                if 'tcp' in host_data:
                    for port_num, port_data in host_data['tcp'].items():
                        ports_scanned += 1
                        self._process_port(host, port_num, 'tcp', port_data)
                
                if 'udp' in host_data:
                    for port_num, port_data in host_data['udp'].items():
                        ports_scanned += 1
                        self._process_port(host, port_num, 'udp', port_data)
                
                # Check for vulnerabilities in script results
                vulnerabilities_found += self._process_vulnerabilities(host, host_data)
        
        return {
            'hosts_discovered': hosts_discovered,
            'ports_scanned': ports_scanned,
            'vulnerabilities_found': vulnerabilities_found
        }
    
    def _process_port(self, host: DiscoveredHost, port_num: int, protocol: str, port_data: Dict):
        """Process individual port information"""
        port, created = DiscoveredPort.objects.get_or_create(
            host=host,
            port_number=port_num,
            protocol=protocol,
            defaults={
                'state': port_data.get('state', 'closed'),
                'service_name': port_data.get('name', ''),
                'service_version': port_data.get('version', ''),
                'service_info': {
                    'product': port_data.get('product', ''),
                    'extrainfo': port_data.get('extrainfo', ''),
                    'conf': port_data.get('conf', '')
                },
                'banner': port_data.get('script', {}).get('banner', '')
            }
        )
        
        # Check for suspicious services or configurations
        self._check_port_security(port, port_data)
    
    def _process_vulnerabilities(self, host: DiscoveredHost, host_data: Dict) -> int:
        """Process vulnerability information from scan scripts"""
        vuln_count = 0
        
        # Check for script results that might indicate vulnerabilities
        for port_data in host_data.get('tcp', {}).values():
            scripts = port_data.get('script', {})
            
            for script_name, script_output in scripts.items():
                if self._is_vulnerability_script(script_name):
                    vuln_count += self._create_vulnerability_from_script(
                        host, script_name, script_output
                    )
        
        return vuln_count
    
    def _is_vulnerability_script(self, script_name: str) -> bool:
        """Check if script name indicates vulnerability detection"""
        vuln_scripts = [
            'vuln', 'ssl-cert', 'ssl-enum-ciphers', 'http-vuln',
            'smb-vuln', 'ftp-anon', 'telnet-encryption'
        ]
        return any(vuln_script in script_name for vuln_script in vuln_scripts)
    
    def _create_vulnerability_from_script(self, host: DiscoveredHost, script_name: str, script_output: str) -> int:
        """Create vulnerability record from script output"""
        # This is a simplified version - in production, you'd parse specific script outputs
        severity_map = {
            'critical': ('critical', 9.0),
            'high': ('high', 7.0),
            'medium': ('medium', 5.0),
            'low': ('low', 3.0),
            'info': ('info', 1.0)
        }
        
        # Determine severity based on script output
        severity = 'info'
        cvss_score = 1.0
        
        for sev_keyword, (sev_level, score) in severity_map.items():
            if sev_keyword in script_output.lower():
                severity = sev_level
                cvss_score = score
                break
        
        # Create vulnerability record
        Vulnerability.objects.create(
            port=host.ports.first(),  # Associate with first port as default
            title=f"Vulnerability detected by {script_name}",
            description=script_output[:500],  # Truncate description
            severity=severity,
            cvss_score=cvss_score
        )
        
        return 1
    
    def _check_port_security(self, port: DiscoveredPort, port_data: Dict):
        """Check for security issues with discovered ports"""
        # Check for default credentials, weak configurations, etc.
        security_issues = []
        
        # Check for anonymous FTP
        if port.port_number == 21 and 'ftp' in port.service_name.lower():
            if 'anonymous' in port_data.get('script', {}).get('ftp-anon', ''):
                security_issues.append('Anonymous FTP access enabled')
        
        # Check for unencrypted services
        unencrypted_services = {
            21: 'FTP', 23: 'Telnet', 80: 'HTTP', 110: 'POP3', 143: 'IMAP'
        }
        
        if port.port_number in unencrypted_services and port.state == 'open':
            service_name = unencrypted_services[port.port_number]
            security_issues.append(f'Unencrypted {service_name} service detected')
        
        # Create alerts for security issues
        for issue in security_issues:
            NetworkAlert.objects.create(
                alert_type='policy_violation',
                severity='medium',
                title=f'Security Issue on {port.host.ip_address}:{port.port_number}',
                description=issue,
                source_ip=port.host.ip_address,
                metadata={'port': port.port_number, 'service': port.service_name}
            )
    
    def _extract_mac_address(self, host_data: Dict) -> str:
        """Extract MAC address from host data"""
        addresses = host_data.get('addresses', {})
        return addresses.get('mac', '')
    
    def _extract_os_info(self, host_data: Dict) -> Dict:
        """Extract OS detection information"""
        os_info = {}
        if 'osmatch' in host_data:
            matches = host_data['osmatch']
            if matches:
                best_match = max(matches, key=lambda x: int(x.get('accuracy', 0)))
                os_info = {
                    'name': best_match.get('name', ''),
                    'accuracy': best_match.get('accuracy', ''),
                    'line': best_match.get('line', '')
                }
        return os_info
    
    def _extract_response_time(self, host_data: Dict) -> Optional[float]:
        """Extract response time from host data"""
        # This would need to be implemented based on nmap output structure
        return None
    
    def start_continuous_monitoring(self, targets: List[str], interval: int = 300):
        """Start continuous monitoring of specified targets"""
        def monitoring_loop():
            while True:
                for target in targets:
                    try:
                        # Perform quick scan for monitoring
                        results = self.nm.scan(hosts=target, arguments="-sn")
                        self._process_monitoring_results(target, results)
                    except Exception as e:
                        logger.error(f"Error monitoring target {target}: {str(e)}")
                
                time.sleep(interval)
        
        monitoring_thread = threading.Thread(target=monitoring_loop)
        monitoring_thread.daemon = True
        monitoring_thread.start()
    
    def _process_monitoring_results(self, target: str, results: Dict):
        """Process continuous monitoring results"""
        # Update host status and detect changes
        for host_ip in results['scan']:
            host_data = results['scan'][host_ip]
            current_state = host_data['status']['state']
            
            # Check for state changes and create alerts if necessary
            try:
                last_host = DiscoveredHost.objects.filter(
                    ip_address=host_ip
                ).order_by('-last_seen').first()
                
                if last_host and last_host.state != current_state:
                    NetworkAlert.objects.create(
                        alert_type='anomaly',
                        severity='medium',
                        title=f'Host state changed: {host_ip}',
                        description=f'Host {host_ip} changed from {last_host.state} to {current_state}',
                        source_ip=host_ip,
                        metadata={'previous_state': last_host.state, 'new_state': current_state}
                    )
            except Exception as e:
                logger.error(f"Error processing monitoring results for {host_ip}: {str(e)}")

# Initialize scanner instance (will be created on first use to avoid import errors)
network_scanner = None

def get_network_scanner():
    """Get or create the network scanner instance"""
    global network_scanner
    if network_scanner is None:
        network_scanner = NetworkScanner()
    return network_scanner

class NetworkScanningService:
    """Service for managing network scans"""
    
    def __init__(self):
        self.scanner = None
    
    def get_scanner(self):
        """Get or create the network scanner instance"""
        if self.scanner is None:
            self.scanner = get_network_scanner()
        return self.scanner
    
    def start_scan(self, scan_id: int):
        """Start a network scan"""
        try:
            from .models import NetworkScan
            scan = NetworkScan.objects.get(id=scan_id)
            scanner = self.get_scanner()
            
            # Update scan status
            scan.status = 'running'
            scan.save()
            
            # Perform the scan
            results = scanner.scan_target(scan.target.target, scan.target.scan_type, scan.target.ports)
            
            # Process results
            hosts_discovered = scanner.process_scan_results(scan, results)
            
            # Update scan completion
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            scan.duration = scan.completed_at - scan.started_at
            scan.hosts_discovered = hosts_discovered
            scan.save()
            
        except Exception as e:
            logger.error(f"Error in scan {scan_id}: {str(e)}")
            try:
                scan.status = 'failed'
                scan.error_message = str(e)
                scan.completed_at = timezone.now()
                scan.duration = scan.completed_at - scan.started_at
                scan.save()
            except:
                pass