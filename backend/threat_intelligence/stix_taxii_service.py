"""
STIX/TAXII Threat Intelligence Integration
"""
import json
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from django.utils import timezone
from django.conf import settings
import logging

# STIX/TAXII Libraries
try:
    import stix2
    from taxii2client.v20 import Server, Collection
    from taxii2client.v21 import Server as ServerV21, Collection as CollectionV21
except ImportError:
    stix2 = None
    Server = None
    Collection = None
    ServerV21 = None
    CollectionV21 = None

from threat_intelligence.models import (
    ThreatFeed, IndicatorOfCompromise, ThreatActor, 
    ThreatCampaign, ThreatIntelligenceReport
)

logger = logging.getLogger('osrovnet.threat_intel')

class STIXTAXIIManager:
    """
    STIX/TAXII protocol manager for threat intelligence feeds
    """
    
    def __init__(self):
        self.servers = {}
        self.collections = {}
        
        # STIX object type mapping
        self.stix_mappings = {
            'indicator': self._process_stix_indicator,
            'malware': self._process_stix_malware,
            'threat-actor': self._process_stix_threat_actor,
            'campaign': self._process_stix_campaign,
            'attack-pattern': self._process_stix_attack_pattern,
            'intrusion-set': self._process_stix_intrusion_set,
        }
    
    def register_taxii_server(self, feed_id: int, server_url: str, username: str = None, 
                             password: str = None, api_key: str = None) -> bool:
        """
        Register a TAXII server for threat intelligence collection
        """
        try:
            if not stix2:
                logger.error("STIX2 library not available. Please install stix2 package.")
                return False
            
            # Try TAXII 2.1 first, then fall back to 2.0
            try:
                if username and password:
                    server = ServerV21(server_url, user=username, password=password)
                elif api_key:
                    server = ServerV21(server_url, headers={'Authorization': f'Bearer {api_key}'})
                else:
                    server = ServerV21(server_url)
                
                # Test connection
                api_roots = server.api_roots
                logger.info(f"Connected to TAXII 2.1 server: {server_url}")
                
            except Exception:
                # Fall back to TAXII 2.0
                if username and password:
                    server = Server(server_url, user=username, password=password)
                elif api_key:
                    server = Server(server_url, headers={'Authorization': f'Bearer {api_key}'})
                else:
                    server = Server(server_url)
                
                api_roots = server.api_roots
                logger.info(f"Connected to TAXII 2.0 server: {server_url}")
            
            self.servers[feed_id] = server
            
            # Update threat feed
            feed = ThreatFeed.objects.get(id=feed_id)
            feed.status = 'active'
            feed.metadata.update({
                'taxii_server': server_url,
                'api_roots': [str(root.url) for root in api_roots],
                'taxii_version': '2.1' if isinstance(server, ServerV21) else '2.0'
            })
            feed.save()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to register TAXII server {server_url}: {str(e)}")
            return False
    
    def fetch_stix_objects(self, feed_id: int, collection_id: str = None, 
                          added_after: datetime = None) -> List[Dict]:
        """
        Fetch STIX objects from TAXII server
        """
        try:
            if feed_id not in self.servers:
                logger.error(f"TAXII server not registered for feed {feed_id}")
                return []
            
            server = self.servers[feed_id]
            stix_objects = []
            
            # Get collections
            if collection_id:
                # Use specific collection
                for api_root in server.api_roots:
                    collections = api_root.collections
                    target_collection = next(
                        (c for c in collections if c.id == collection_id), None
                    )
                    if target_collection:
                        objects = self._fetch_from_collection(target_collection, added_after)
                        stix_objects.extend(objects)
            else:
                # Fetch from all collections
                for api_root in server.api_roots:
                    for collection in api_root.collections:
                        objects = self._fetch_from_collection(collection, added_after)
                        stix_objects.extend(objects)
            
            logger.info(f"Fetched {len(stix_objects)} STIX objects from feed {feed_id}")
            return stix_objects
            
        except Exception as e:
            logger.error(f"Failed to fetch STIX objects: {str(e)}")
            return []
    
    def process_stix_bundle(self, bundle_data: Dict, feed_id: int) -> Dict:
        """
        Process a STIX bundle and create corresponding database objects
        """
        try:
            feed = ThreatFeed.objects.get(id=feed_id)
            results = {
                'indicators': 0,
                'threat_actors': 0,
                'campaigns': 0,
                'malware': 0,
                'reports': 0,
                'errors': []
            }
            
            # Parse STIX bundle
            if isinstance(bundle_data, str):
                bundle = stix2.parse(bundle_data)
            else:
                bundle = stix2.Bundle(**bundle_data)
            
            # Process each object in bundle
            for obj in bundle.objects:
                try:
                    obj_type = obj.type
                    if obj_type in self.stix_mappings:
                        processed = self.stix_mappings[obj_type](obj, feed)
                        if processed:
                            if obj_type == 'indicator':
                                results['indicators'] += 1
                            elif obj_type == 'threat-actor':
                                results['threat_actors'] += 1
                            elif obj_type == 'campaign':
                                results['campaigns'] += 1
                            elif obj_type == 'malware':
                                results['malware'] += 1
                            elif obj_type in ['report', 'analysis-report']:
                                results['reports'] += 1
                    
                except Exception as e:
                    error_msg = f"Error processing {obj.type} object {obj.id}: {str(e)}"
                    results['errors'].append(error_msg)
                    logger.warning(error_msg)
            
            # Update feed timestamp
            feed.last_updated = timezone.now()
            feed.save()
            
            logger.info(f"Processed STIX bundle: {results}")
            return results
            
        except Exception as e:
            logger.error(f"Failed to process STIX bundle: {str(e)}")
            return {'error': str(e)}
    
    def create_stix_indicator(self, ioc: IndicatorOfCompromise) -> Optional[str]:
        """
        Create a STIX indicator from an IOC
        """
        try:
            # Map IOC type to STIX pattern
            pattern_mapping = {
                'ip': f"[ipv4-addr:value = '{ioc.value}']",
                'domain': f"[domain-name:value = '{ioc.value}']",
                'url': f"[url:value = '{ioc.value}']",
                'hash_md5': f"[file:hashes.MD5 = '{ioc.value}']",
                'hash_sha1': f"[file:hashes.SHA-1 = '{ioc.value}']",
                'hash_sha256': f"[file:hashes.SHA-256 = '{ioc.value}']",
                'email': f"[email-addr:value = '{ioc.value}']",
            }
            
            if ioc.ioc_type not in pattern_mapping:
                logger.warning(f"Unsupported IOC type for STIX: {ioc.ioc_type}")
                return None
            
            pattern = pattern_mapping[ioc.ioc_type]
            
            # Create STIX indicator
            indicator = stix2.Indicator(
                pattern=pattern,
                labels=[ioc.threat_type],
                created=ioc.first_seen,
                modified=ioc.last_seen,
                description=ioc.description,
                confidence=ioc.confidence,
                external_references=[
                    {
                        "source_name": ioc.source_feed.name if ioc.source_feed else "OSROVNet",
                        "description": f"IOC from {ioc.source_feed.name if ioc.source_feed else 'OSROVNet'}"
                    }
                ]
            )
            
            return indicator.serialize(pretty=True)
            
        except Exception as e:
            logger.error(f"Failed to create STIX indicator: {str(e)}")
            return None
    
    def export_stix_bundle(self, feed_id: int, days_back: int = 7) -> Optional[str]:
        """
        Export IOCs as a STIX bundle
        """
        try:
            feed = ThreatFeed.objects.get(id=feed_id)
            cutoff_date = timezone.now() - timedelta(days=days_back)
            
            # Get recent IOCs
            iocs = IndicatorOfCompromise.objects.filter(
                source_feed=feed,
                last_seen__gte=cutoff_date,
                status='active'
            )
            
            stix_objects = []
            
            # Convert IOCs to STIX indicators
            for ioc in iocs:
                stix_indicator = self.create_stix_indicator(ioc)
                if stix_indicator:
                    indicator_obj = stix2.parse(stix_indicator)
                    stix_objects.append(indicator_obj)
            
            # Create bundle
            bundle = stix2.Bundle(
                objects=stix_objects,
                id=f"bundle--{feed.id}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            )
            
            return bundle.serialize(pretty=True)
            
        except Exception as e:
            logger.error(f"Failed to export STIX bundle: {str(e)}")
            return None
    
    def _fetch_from_collection(self, collection, added_after: datetime = None) -> List[Dict]:
        """
        Fetch objects from a specific TAXII collection
        """
        try:
            # Build filter parameters
            kwargs = {}
            if added_after:
                kwargs['added_after'] = added_after
            
            # Fetch objects
            objects = collection.get_objects(**kwargs)
            
            stix_objects = []
            for obj in objects['objects']:
                stix_objects.append(obj)
            
            return stix_objects
            
        except Exception as e:
            logger.error(f"Failed to fetch from collection {collection.id}: {str(e)}")
            return []
    
    def _process_stix_indicator(self, indicator, feed: ThreatFeed) -> bool:
        """
        Process a STIX indicator object
        """
        try:
            # Parse pattern to extract IOC value and type
            pattern = indicator.pattern
            ioc_info = self._parse_stix_pattern(pattern)
            
            if not ioc_info:
                return False
            
            # Create or update IOC
            ioc, created = IndicatorOfCompromise.objects.get_or_create(
                value=ioc_info['value'],
                ioc_type=ioc_info['type'],
                source_feed=feed,
                defaults={
                    'threat_type': indicator.labels[0] if indicator.labels else 'suspicious',
                    'severity': self._map_stix_severity(indicator),
                    'confidence': getattr(indicator, 'confidence', 50),
                    'description': getattr(indicator, 'description', ''),
                    'first_seen': indicator.created,
                    'last_seen': indicator.modified or indicator.created,
                    'context': {
                        'stix_id': indicator.id,
                        'labels': indicator.labels,
                        'pattern': pattern
                    }
                }
            )
            
            if not created:
                # Update existing IOC
                ioc.last_seen = indicator.modified or indicator.created
                ioc.confidence = max(ioc.confidence, getattr(indicator, 'confidence', 50))
                ioc.save()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to process STIX indicator: {str(e)}")
            return False
    
    def _process_stix_threat_actor(self, actor, feed: ThreatFeed) -> bool:
        """
        Process a STIX threat actor object
        """
        try:
            threat_actor, created = ThreatActor.objects.get_or_create(
                name=actor.name,
                defaults={
                    'actor_type': 'apt',  # Default to APT
                    'description': getattr(actor, 'description', ''),
                    'aliases': getattr(actor, 'aliases', []),
                    'first_seen': actor.created,
                    'last_activity': actor.modified or actor.created,
                    'metadata': {
                        'stix_id': actor.id,
                        'source_feed': feed.name
                    }
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to process STIX threat actor: {str(e)}")
            return False
    
    def _process_stix_campaign(self, campaign, feed: ThreatFeed) -> bool:
        """
        Process a STIX campaign object
        """
        try:
            threat_campaign, created = ThreatCampaign.objects.get_or_create(
                name=campaign.name,
                defaults={
                    'description': getattr(campaign, 'description', ''),
                    'first_seen': campaign.created,
                    'last_seen': campaign.modified or campaign.created,
                    'status': 'unknown',
                    'metadata': {
                        'stix_id': campaign.id,
                        'source_feed': feed.name
                    }
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to process STIX campaign: {str(e)}")
            return False
    
    def _process_stix_malware(self, malware, feed: ThreatFeed) -> bool:
        """
        Process a STIX malware object
        """
        try:
            # Create threat intelligence report for malware
            report, created = ThreatIntelligenceReport.objects.get_or_create(
                title=f"Malware: {malware.name}",
                defaults={
                    'report_type': 'malware',
                    'content': getattr(malware, 'description', ''),
                    'severity': 'high',
                    'metadata': {
                        'stix_id': malware.id,
                        'malware_labels': getattr(malware, 'labels', []),
                        'source_feed': feed.name
                    }
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to process STIX malware: {str(e)}")
            return False
    
    def _process_stix_attack_pattern(self, pattern, feed: ThreatFeed) -> bool:
        """
        Process a STIX attack pattern object
        """
        try:
            # Store as threat intelligence report
            report, created = ThreatIntelligenceReport.objects.get_or_create(
                title=f"Attack Pattern: {pattern.name}",
                defaults={
                    'report_type': 'general',
                    'content': getattr(pattern, 'description', ''),
                    'severity': 'medium',
                    'metadata': {
                        'stix_id': pattern.id,
                        'kill_chain_phases': getattr(pattern, 'kill_chain_phases', []),
                        'source_feed': feed.name
                    }
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to process STIX attack pattern: {str(e)}")
            return False
    
    def _process_stix_intrusion_set(self, intrusion_set, feed: ThreatFeed) -> bool:
        """
        Process a STIX intrusion set object
        """
        try:
            threat_actor, created = ThreatActor.objects.get_or_create(
                name=intrusion_set.name,
                defaults={
                    'actor_type': 'apt',
                    'description': getattr(intrusion_set, 'description', ''),
                    'aliases': getattr(intrusion_set, 'aliases', []),
                    'first_seen': intrusion_set.created,
                    'last_activity': intrusion_set.modified or intrusion_set.created,
                    'metadata': {
                        'stix_id': intrusion_set.id,
                        'source_feed': feed.name
                    }
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to process STIX intrusion set: {str(e)}")
            return False
    
    def _parse_stix_pattern(self, pattern: str) -> Optional[Dict]:
        """
        Parse STIX pattern to extract IOC information
        """
        try:
            # Simple pattern parsing (could be enhanced with proper STIX pattern parser)
            if '[ipv4-addr:value' in pattern:
                value = pattern.split("'")[1]
                return {'type': 'ip', 'value': value}
            elif '[domain-name:value' in pattern:
                value = pattern.split("'")[1]
                return {'type': 'domain', 'value': value}
            elif '[url:value' in pattern:
                value = pattern.split("'")[1]
                return {'type': 'url', 'value': value}
            elif '[file:hashes.MD5' in pattern:
                value = pattern.split("'")[1]
                return {'type': 'hash_md5', 'value': value}
            elif '[file:hashes.SHA-1' in pattern:
                value = pattern.split("'")[1]
                return {'type': 'hash_sha1', 'value': value}
            elif '[file:hashes.SHA-256' in pattern:
                value = pattern.split("'")[1]
                return {'type': 'hash_sha256', 'value': value}
            elif '[email-addr:value' in pattern:
                value = pattern.split("'")[1]
                return {'type': 'email', 'value': value}
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to parse STIX pattern: {str(e)}")
            return None
    
    def _map_stix_severity(self, indicator) -> str:
        """
        Map STIX indicator properties to severity level
        """
        confidence = getattr(indicator, 'confidence', 50)
        labels = getattr(indicator, 'labels', [])
        
        # High confidence malicious indicators
        if confidence >= 80 and any(label in ['malicious-activity', 'malware'] for label in labels):
            return 'critical'
        elif confidence >= 60:
            return 'high'
        elif confidence >= 40:
            return 'medium'
        else:
            return 'low'

# Singleton instance
stix_taxii_manager = STIXTAXIIManager()