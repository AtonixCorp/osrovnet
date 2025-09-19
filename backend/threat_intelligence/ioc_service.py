"""
IOC (Indicators of Compromise) Management Service
"""
import re
import json
import requests
import hashlib
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from django.utils import timezone
from django.db.models import Q
import logging

from .models import (
    ThreatFeed, IndicatorOfCompromise, ThreatMatch, 
    ThreatActor, ThreatCampaign
)

logger = logging.getLogger('osrovnet.threat_intel')

class IOCManager:
    """
    Comprehensive IOC Management System
    """
    
    def __init__(self):
        self.ioc_validators = {
            'ip': self._validate_ip,
            'domain': self._validate_domain,
            'url': self._validate_url,
            'hash_md5': self._validate_md5,
            'hash_sha1': self._validate_sha1,
            'hash_sha256': self._validate_sha256,
            'email': self._validate_email,
        }
        
        # IOC enrichment sources
        self.enrichment_sources = {
            'virustotal': self._enrich_virustotal,
            'otx': self._enrich_otx,
            'abuse_ch': self._enrich_abuse_ch,
        }
        
        # Pattern matching for IOC extraction
        self.ioc_patterns = {
            'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domain': r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b',
            'url': r'https?://[^\s<>"{}|\\^`[\]]+',
            'hash_md5': r'\b[a-fA-F0-9]{32}\b',
            'hash_sha1': r'\b[a-fA-F0-9]{40}\b',
            'hash_sha256': r'\b[a-fA-F0-9]{64}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        }
    
    def create_ioc(self, ioc_data: Dict, source_feed: ThreatFeed = None, user=None) -> IndicatorOfCompromise:
        """
        Create a new IOC with validation and enrichment
        
        Args:
            ioc_data: Dictionary containing IOC information
            source_feed: Source threat feed (optional)
            user: User creating the IOC (optional)
        """
        try:
            # Validate IOC format
            ioc_type = ioc_data.get('ioc_type')
            value = ioc_data.get('value', '').strip()
            
            if not self._validate_ioc(value, ioc_type):
                raise ValueError(f"Invalid {ioc_type} format: {value}")
            
            # Normalize IOC value
            normalized_value = self._normalize_ioc(value, ioc_type)
            
            # Check for existing IOC
            existing_ioc = IndicatorOfCompromise.objects.filter(
                value=normalized_value,
                ioc_type=ioc_type
            ).first()
            
            if existing_ioc:
                # Update existing IOC
                existing_ioc.last_seen = timezone.now()
                existing_ioc.confidence = max(existing_ioc.confidence, ioc_data.get('confidence', 50))
                existing_ioc.save()
                logger.info(f"Updated existing IOC: {normalized_value}")
                return existing_ioc
            
            # Create new IOC
            ioc = IndicatorOfCompromise.objects.create(
                value=normalized_value,
                ioc_type=ioc_type,
                threat_type=ioc_data.get('threat_type', 'suspicious'),
                severity=ioc_data.get('severity', 'medium'),
                confidence=ioc_data.get('confidence', 50),
                description=ioc_data.get('description', ''),
                tags=ioc_data.get('tags', []),
                context=ioc_data.get('context', {}),
                tlp=ioc_data.get('tlp', 'white'),
                source_feed=source_feed,
                created_by=user,
                expires_at=ioc_data.get('expires_at')
            )
            
            # Enrich IOC with external sources
            self._enrich_ioc(ioc)
            
            logger.info(f"Created new IOC: {normalized_value} ({ioc_type})")
            return ioc
            
        except Exception as e:
            logger.error(f"Failed to create IOC: {str(e)}")
            raise
    
    def bulk_import_iocs(self, iocs_data: List[Dict], source_feed: ThreatFeed, user=None) -> Dict:
        """
        Bulk import IOCs from threat feeds
        
        Args:
            iocs_data: List of IOC dictionaries
            source_feed: Source threat feed
            user: User importing IOCs
        """
        results = {
            'imported': 0,
            'updated': 0,
            'failed': 0,
            'errors': []
        }
        
        for ioc_data in iocs_data:
            try:
                existing_count = IndicatorOfCompromise.objects.filter(
                    value=ioc_data.get('value'),
                    ioc_type=ioc_data.get('ioc_type')
                ).count()
                
                ioc = self.create_ioc(ioc_data, source_feed, user)
                
                if existing_count > 0:
                    results['updated'] += 1
                else:
                    results['imported'] += 1
                    
            except Exception as e:
                results['failed'] += 1
                results['errors'].append(f"Failed to import {ioc_data.get('value', 'unknown')}: {str(e)}")
        
        logger.info(f"Bulk import completed: {results['imported']} imported, {results['updated']} updated, {results['failed']} failed")
        return results
    
    def extract_iocs_from_text(self, text: str) -> Dict[str, List[str]]:
        """
        Extract IOCs from unstructured text using regex patterns
        
        Args:
            text: Text to extract IOCs from
            
        Returns:
            Dictionary with IOC types as keys and lists of extracted values
        """
        extracted_iocs = {}
        
        for ioc_type, pattern in self.ioc_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Remove duplicates and validate
                validated_matches = []
                for match in set(matches):
                    if self._validate_ioc(match, ioc_type):
                        validated_matches.append(self._normalize_ioc(match, ioc_type))
                
                if validated_matches:
                    extracted_iocs[ioc_type] = validated_matches
        
        return extracted_iocs
    
    def search_iocs(self, query: str, filters: Dict = None) -> List[IndicatorOfCompromise]:
        """
        Search IOCs with advanced filtering
        
        Args:
            query: Search query
            filters: Additional filters (threat_type, severity, etc.)
        """
        queryset = IndicatorOfCompromise.objects.filter(status='active')
        
        # Text search
        if query:
            queryset = queryset.filter(
                Q(value__icontains=query) |
                Q(description__icontains=query)
                # Remove tags search for SQLite compatibility
                # Q(tags__contains=[query])
            )
        
        # Apply filters
        if filters:
            if filters.get('ioc_type'):
                queryset = queryset.filter(ioc_type=filters['ioc_type'])
            if filters.get('threat_type'):
                queryset = queryset.filter(threat_type=filters['threat_type'])
            if filters.get('severity'):
                queryset = queryset.filter(severity=filters['severity'])
            if filters.get('source_feed'):
                queryset = queryset.filter(source_feed_id=filters['source_feed'])
            if filters.get('date_from'):
                queryset = queryset.filter(first_seen__gte=filters['date_from'])
        
        return queryset.order_by('-first_seen')
    
    def check_ioc_matches(self, value: str, ioc_type: str = None) -> List[ThreatMatch]:
        """
        Check if a value matches any known IOCs
        
        Args:
            value: Value to check against IOCs
            ioc_type: Specific IOC type to check (optional)
        """
        matches = []
        
        # Normalize the input value
        normalized_value = self._normalize_ioc(value, ioc_type)
        
        # Build query
        query = Q(status='active', value=normalized_value)
        if ioc_type:
            query &= Q(ioc_type=ioc_type)
        
        # Find exact matches
        matching_iocs = IndicatorOfCompromise.objects.filter(query)
        
        for ioc in matching_iocs:
            # Check if match already exists
            existing_match = ThreatMatch.objects.filter(
                ioc=ioc,
                matched_value=normalized_value
            ).first()
            
            if existing_match:
                # Update existing match
                existing_match.last_seen = timezone.now()
                existing_match.count += 1
                existing_match.save()
                matches.append(existing_match)
            else:
                # Create new match
                match = ThreatMatch.objects.create(
                    ioc=ioc,
                    match_type='exact',
                    matched_value=normalized_value,
                    confidence=ioc.confidence,
                    event_data={'checked_at': timezone.now().isoformat()}
                )
                matches.append(match)
        
        # Check for partial matches (domains, URLs)
        if ioc_type in ['domain', 'url'] or not ioc_type:
            partial_matches = self._check_partial_matches(normalized_value)
            matches.extend(partial_matches)
        
        return matches
    
    def enrich_ioc_context(self, ioc: IndicatorOfCompromise) -> Dict:
        """
        Enrich IOC with additional context from external sources
        
        Args:
            ioc: IOC to enrich
            
        Returns:
            Dictionary with enrichment data
        """
        enrichment_data = {}
        
        for source_name, enrichment_func in self.enrichment_sources.items():
            try:
                source_data = enrichment_func(ioc.value, ioc.ioc_type)
                if source_data:
                    enrichment_data[source_name] = source_data
            except Exception as e:
                logger.warning(f"Failed to enrich IOC {ioc.value} from {source_name}: {str(e)}")
        
        # Update IOC context
        if enrichment_data:
            ioc.context.update(enrichment_data)
            ioc.save()
        
        return enrichment_data
    
    def expire_old_iocs(self, days: int = 90) -> int:
        """
        Mark old IOCs as expired
        
        Args:
            days: Number of days after which IOCs expire
            
        Returns:
            Number of IOCs expired
        """
        cutoff_date = timezone.now() - timedelta(days=days)
        
        expired_count = IndicatorOfCompromise.objects.filter(
            status='active',
            last_seen__lt=cutoff_date
        ).update(status='expired')
        
        logger.info(f"Expired {expired_count} old IOCs")
        return expired_count
    
    def get_ioc_statistics(self) -> Dict:
        """Get IOC statistics for dashboard"""
        stats = {}
        
        # Total counts
        stats['total_iocs'] = IndicatorOfCompromise.objects.count()
        stats['active_iocs'] = IndicatorOfCompromise.objects.filter(status='active').count()
        
        # By type
        ioc_types = IndicatorOfCompromise.objects.values('ioc_type').distinct()
        stats['by_type'] = {}
        for ioc_type in ioc_types:
            type_name = ioc_type['ioc_type']
            count = IndicatorOfCompromise.objects.filter(ioc_type=type_name, status='active').count()
            stats['by_type'][type_name] = count
        
        # By severity
        severities = ['critical', 'high', 'medium', 'low', 'info']
        stats['by_severity'] = {}
        for severity in severities:
            count = IndicatorOfCompromise.objects.filter(severity=severity, status='active').count()
            stats['by_severity'][severity] = count
        
        # Recent matches
        recent_matches = ThreatMatch.objects.filter(
            first_seen__gte=timezone.now() - timedelta(hours=24)
        ).count()
        stats['recent_matches'] = recent_matches
        
        return stats
    
    def _validate_ioc(self, value: str, ioc_type: str) -> bool:
        """Validate IOC format"""
        if ioc_type in self.ioc_validators:
            return self.ioc_validators[ioc_type](value)
        return bool(value.strip())
    
    def _normalize_ioc(self, value: str, ioc_type: str) -> str:
        """Normalize IOC value"""
        normalized = value.strip().lower()
        
        if ioc_type in ['hash_md5', 'hash_sha1', 'hash_sha256']:
            return normalized
        elif ioc_type == 'ip':
            return normalized
        elif ioc_type == 'domain':
            return normalized.rstrip('.')
        elif ioc_type == 'email':
            return normalized
        
        return normalized
    
    def _validate_ip(self, value: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(value)
            return True
        except:
            return False
    
    def _validate_domain(self, value: str) -> bool:
        """Validate domain name"""
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, value)) and len(value) <= 253
    
    def _validate_url(self, value: str) -> bool:
        """Validate URL"""
        url_pattern = r'^https?://[^\s<>"{}|\\^`[\]]+$'
        return bool(re.match(url_pattern, value))
    
    def _validate_md5(self, value: str) -> bool:
        """Validate MD5 hash"""
        return bool(re.match(r'^[a-fA-F0-9]{32}$', value))
    
    def _validate_sha1(self, value: str) -> bool:
        """Validate SHA1 hash"""
        return bool(re.match(r'^[a-fA-F0-9]{40}$', value))
    
    def _validate_sha256(self, value: str) -> bool:
        """Validate SHA256 hash"""
        return bool(re.match(r'^[a-fA-F0-9]{64}$', value))
    
    def _validate_email(self, value: str) -> bool:
        """Validate email address"""
        email_pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$'
        return bool(re.match(email_pattern, value))
    
    def _enrich_ioc(self, ioc: IndicatorOfCompromise):
        """Enrich IOC with external data"""
        try:
            enrichment_data = self.enrich_ioc_context(ioc)
            logger.debug(f"Enriched IOC {ioc.value} with {len(enrichment_data)} sources")
        except Exception as e:
            logger.warning(f"Failed to enrich IOC {ioc.value}: {str(e)}")
    
    def _enrich_virustotal(self, value: str, ioc_type: str) -> Optional[Dict]:
        """Enrich IOC using VirusTotal API"""
        # Placeholder for VirusTotal integration
        # In production, you'd implement actual VT API calls
        return {
            'source': 'virustotal',
            'scanned': False,
            'detection_ratio': None,
            'scan_date': None
        }
    
    def _enrich_otx(self, value: str, ioc_type: str) -> Optional[Dict]:
        """Enrich IOC using AlienVault OTX"""
        # Placeholder for OTX integration
        return {
            'source': 'otx',
            'pulses': [],
            'reputation': None
        }
    
    def _enrich_abuse_ch(self, value: str, ioc_type: str) -> Optional[Dict]:
        """Enrich IOC using Abuse.ch feeds"""
        # Placeholder for Abuse.ch integration
        return {
            'source': 'abuse_ch',
            'listed': False,
            'category': None
        }
    
    def _check_partial_matches(self, value: str) -> List[ThreatMatch]:
        """Check for partial matches (subdomains, URL components)"""
        matches = []
        
        # For domains, check if it's a subdomain of any IOC
        if '.' in value:
            domain_parts = value.split('.')
            for i in range(len(domain_parts)):
                parent_domain = '.'.join(domain_parts[i:])
                
                matching_iocs = IndicatorOfCompromise.objects.filter(
                    status='active',
                    ioc_type='domain',
                    value=parent_domain
                )
                
                for ioc in matching_iocs:
                    match = ThreatMatch.objects.create(
                        ioc=ioc,
                        match_type='partial',
                        matched_value=value,
                        confidence=max(ioc.confidence - 20, 10),  # Lower confidence for partial matches
                        event_data={'match_reason': 'subdomain_match'}
                    )
                    matches.append(match)
        
        return matches

# Singleton instance
ioc_manager = IOCManager()