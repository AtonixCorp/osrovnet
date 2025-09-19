"""
Network Topology Mapping and Visualization Service
"""
import ipaddress
import subprocess
import threading
import time
import logging
from typing import Dict, List, Tuple, Optional
from django.utils import timezone
from .models import NetworkTopology, NetworkNode, NetworkConnection, DiscoveredHost

logger = logging.getLogger('osrovnet.topology')

class NetworkTopologyMapper:
    """
    Advanced network topology discovery and mapping service
    """
    
    def __init__(self):
        self.discovery_methods = {
            'traceroute': self._traceroute_discovery,
            'arp_scan': self._arp_scan_discovery,
            'ping_sweep': self._ping_sweep_discovery,
            'route_analysis': self._route_analysis,
        }
    
    def discover_topology(self, network_range: str, topology_name: str, 
                         user, methods: List[str] = None) -> NetworkTopology:
        """
        Discover and map network topology for a given network range
        
        Args:
            network_range: Network CIDR (e.g., '192.168.1.0/24')
            topology_name: Name for the topology
            user: User creating the topology
            methods: Discovery methods to use
        """
        if methods is None:
            methods = ['ping_sweep', 'arp_scan', 'traceroute']
        
        logger.info(f"Starting topology discovery for {network_range}")
        
        # Create topology record
        topology = NetworkTopology.objects.create(
            name=topology_name,
            network_range=network_range,
            created_by=user,
            topology_data={}
        )
        
        # Discover hosts and connections
        discovered_data = {}
        for method in methods:
            if method in self.discovery_methods:
                logger.info(f"Running {method} discovery")
                method_data = self.discovery_methods[method](network_range)
                discovered_data[method] = method_data
        
        # Process and create topology
        self._process_topology_data(topology, discovered_data, network_range)
        
        logger.info(f"Topology discovery completed for {topology.name}")
        return topology
    
    def _ping_sweep_discovery(self, network_range: str) -> Dict:
        """Discover live hosts using ping sweep"""
        live_hosts = []
        
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            
            for ip in network.hosts():
                if self._ping_host(str(ip)):
                    host_info = {
                        'ip': str(ip),
                        'status': 'up',
                        'response_time': self._measure_ping_time(str(ip))
                    }
                    live_hosts.append(host_info)
        
        except Exception as e:
            logger.error(f"Ping sweep failed: {str(e)}")
        
        return {'live_hosts': live_hosts}
    
    def _arp_scan_discovery(self, network_range: str) -> Dict:
        """Discover hosts using ARP scanning"""
        arp_entries = []
        
        try:
            # Use nmap for ARP scanning
            cmd = f"nmap -sn -PR {network_range}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                arp_entries = self._parse_arp_results(result.stdout)
        
        except Exception as e:
            logger.error(f"ARP scan failed: {str(e)}")
        
        return {'arp_entries': arp_entries}
    
    def _traceroute_discovery(self, network_range: str) -> Dict:
        """Discover network paths using traceroute"""
        routes = []
        
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            
            # Sample a few hosts for traceroute to avoid overwhelming the network
            sample_hosts = list(network.hosts())[:5]
            
            for ip in sample_hosts:
                route = self._traceroute_to_host(str(ip))
                if route:
                    routes.append(route)
        
        except Exception as e:
            logger.error(f"Traceroute discovery failed: {str(e)}")
        
        return {'routes': routes}
    
    def _route_analysis(self, network_range: str) -> Dict:
        """Analyze routing table for network topology"""
        routing_info = {}
        
        try:
            # Get local routing table
            cmd = "ip route show"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                routing_info = self._parse_routing_table(result.stdout)
        
        except Exception as e:
            logger.error(f"Route analysis failed: {str(e)}")
        
        return routing_info
    
    def _ping_host(self, ip: str) -> bool:
        """Check if host responds to ping"""
        try:
            cmd = f"ping -c 1 -W 2 {ip}"
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _measure_ping_time(self, ip: str) -> Optional[float]:
        """Measure ping response time"""
        try:
            cmd = f"ping -c 3 -W 2 {ip}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Parse ping time from output
                lines = result.stdout.split('\\n')
                for line in lines:
                    if 'time=' in line:
                        time_str = line.split('time=')[1].split(' ')[0]
                        return float(time_str)
        except:
            pass
        
        return None
    
    def _traceroute_to_host(self, ip: str) -> Optional[Dict]:
        """Perform traceroute to discover path"""
        try:
            cmd = f"traceroute -n -m 10 {ip}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                hops = self._parse_traceroute_output(result.stdout)
                return {
                    'destination': ip,
                    'hops': hops
                }
        except Exception as e:
            logger.debug(f"Traceroute to {ip} failed: {str(e)}")
        
        return None
    
    def _parse_arp_results(self, output: str) -> List[Dict]:
        """Parse nmap ARP scan results"""
        entries = []
        lines = output.split('\\n')
        
        current_host = None
        for line in lines:
            if 'Nmap scan report for' in line:
                ip = line.split()[-1]
                if ip.startswith('(') and ip.endswith(')'):
                    ip = ip[1:-1]
                current_host = {'ip': ip}
            elif 'MAC Address:' in line and current_host:
                mac_info = line.split('MAC Address: ')[1]
                mac = mac_info.split(' ')[0]
                vendor = mac_info.split('(')[1].split(')')[0] if '(' in mac_info else ''
                current_host['mac'] = mac
                current_host['vendor'] = vendor
                entries.append(current_host)
                current_host = None
        
        return entries
    
    def _parse_traceroute_output(self, output: str) -> List[Dict]:
        """Parse traceroute output"""
        hops = []
        lines = output.split('\\n')
        
        for line in lines:
            if line.strip() and not line.startswith('traceroute'):
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0].isdigit():
                    hop_num = int(parts[0])
                    ip = parts[1] if not parts[1].startswith('*') else None
                    
                    # Extract timing information
                    times = []
                    for part in parts[2:]:
                        if part.endswith('ms'):
                            try:
                                times.append(float(part[:-2]))
                            except:
                                pass
                    
                    if ip:
                        hops.append({
                            'hop': hop_num,
                            'ip': ip,
                            'times': times,
                            'avg_time': sum(times) / len(times) if times else None
                        })
        
        return hops
    
    def _parse_routing_table(self, output: str) -> Dict:
        """Parse system routing table"""
        routes = []
        lines = output.split('\\n')
        
        for line in lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    route_info = {
                        'destination': parts[0],
                        'gateway': parts[2] if parts[2] != '0.0.0.0' else None,
                        'interface': parts[-1] if len(parts) > 3 else None
                    }
                    routes.append(route_info)
        
        return {'routes': routes}
    
    def _process_topology_data(self, topology: NetworkTopology, 
                              discovered_data: Dict, network_range: str):
        """Process discovered data and create topology nodes and connections"""
        nodes_created = {}
        
        # Process live hosts from ping sweep
        if 'ping_sweep' in discovered_data:
            for host in discovered_data['ping_sweep'].get('live_hosts', []):
                node = self._create_or_update_node(
                    topology, host['ip'], 
                    node_type='host',
                    metadata={'ping_time': host.get('response_time')}
                )
                nodes_created[host['ip']] = node
        
        # Add ARP information
        if 'arp_scan' in discovered_data:
            for entry in discovered_data['arp_scan'].get('arp_entries', []):
                ip = entry['ip']
                if ip in nodes_created:
                    node = nodes_created[ip]
                    node.mac_address = entry.get('mac', '')
                    node.metadata.update({
                        'vendor': entry.get('vendor', ''),
                        'discovery_method': 'arp'
                    })
                    node.save()
        
        # Process routing information to identify gateways
        if 'route_analysis' in discovered_data:
            routes = discovered_data['route_analysis'].get('routes', [])
            for route in routes:
                gateway = route.get('gateway')
                if gateway and gateway in nodes_created:
                    node = nodes_created[gateway]
                    node.is_gateway = True
                    node.node_type = 'router'
                    node.save()
        
        # Create connections based on traceroute data
        if 'traceroute' in discovered_data:
            for route in discovered_data['traceroute'].get('routes', []):
                self._create_connections_from_route(topology, route, nodes_created)
        
        # Update topology data
        topology.topology_data = {
            'node_count': len(nodes_created),
            'discovery_summary': {
                method: len(data) if isinstance(data, list) else len(data.keys()) 
                for method, data in discovered_data.items()
            },
            'network_range': network_range,
            'last_discovery': timezone.now().isoformat()
        }
        topology.save()
    
    def _create_or_update_node(self, topology: NetworkTopology, ip: str, 
                              node_type: str = 'unknown', **kwargs) -> NetworkNode:
        """Create or update a network node"""
        node, created = NetworkNode.objects.get_or_create(
            topology=topology,
            ip_address=ip,
            defaults={
                'node_type': node_type,
                'metadata': kwargs.get('metadata', {}),
                'hostname': kwargs.get('hostname', ''),
                'mac_address': kwargs.get('mac_address', ''),
            }
        )
        
        if not created:
            # Update existing node
            for key, value in kwargs.items():
                if hasattr(node, key):
                    setattr(node, key, value)
            node.save()
        
        return node
    
    def _create_connections_from_route(self, topology: NetworkTopology, 
                                     route: Dict, nodes_created: Dict):
        """Create network connections based on traceroute data"""
        hops = route.get('hops', [])
        
        for i in range(len(hops) - 1):
            current_hop = hops[i]
            next_hop = hops[i + 1]
            
            current_ip = current_hop['ip']
            next_ip = next_hop['ip']
            
            # Create nodes if they don't exist
            if current_ip not in nodes_created:
                nodes_created[current_ip] = self._create_or_update_node(
                    topology, current_ip, node_type='router'
                )
            
            if next_ip not in nodes_created:
                nodes_created[next_ip] = self._create_or_update_node(
                    topology, next_ip, node_type='host'
                )
            
            # Create connection
            try:
                connection, created = NetworkConnection.objects.get_or_create(
                    topology=topology,
                    source_node=nodes_created[current_ip],
                    destination_node=nodes_created[next_ip],
                    defaults={
                        'connection_type': 'routed',
                        'latency': next_hop.get('avg_time'),
                        'metadata': {
                            'hop_number': next_hop['hop'],
                            'times': next_hop.get('times', [])
                        }
                    }
                )
            except Exception as e:
                logger.error(f"Failed to create connection {current_ip} -> {next_ip}: {str(e)}")
    
    def get_topology_visualization_data(self, topology_id: int) -> Dict:
        """Get topology data formatted for visualization"""
        try:
            topology = NetworkTopology.objects.get(id=topology_id)
            nodes = list(topology.nodes.all())
            connections = list(topology.connections.all())
            
            # Format nodes for visualization
            vis_nodes = []
            for node in nodes:
                vis_nodes.append({
                    'id': node.id,
                    'label': node.hostname or node.ip_address,
                    'ip': node.ip_address,
                    'type': node.node_type,
                    'mac': node.mac_address,
                    'x': node.position_x,
                    'y': node.position_y,
                    'is_gateway': node.is_gateway,
                    'metadata': node.metadata
                })
            
            # Format connections for visualization
            vis_edges = []
            for conn in connections:
                vis_edges.append({
                    'id': conn.id,
                    'from': conn.source_node.id,
                    'to': conn.destination_node.id,
                    'type': conn.connection_type,
                    'latency': conn.latency,
                    'bandwidth': conn.bandwidth,
                    'metadata': conn.metadata
                })
            
            return {
                'topology': {
                    'id': topology.id,
                    'name': topology.name,
                    'network_range': topology.network_range,
                    'data': topology.topology_data
                },
                'nodes': vis_nodes,
                'edges': vis_edges
            }
        
        except NetworkTopology.DoesNotExist:
            return {'error': 'Topology not found'}
        except Exception as e:
            logger.error(f"Failed to get visualization data: {str(e)}")
            return {'error': str(e)}

# Singleton instance
topology_mapper = NetworkTopologyMapper()