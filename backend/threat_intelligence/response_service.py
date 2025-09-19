"""
Automated Threat Response Service for OSROVNet
"""
import logging
import threading
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from django.utils import timezone
from django.db import transaction
from django.contrib.auth.models import User
from .models import (
    ThreatResponsePlaybook, ThreatResponseExecution, ThreatMatch,
    IndicatorOfCompromise, SystemAlert, ThreatActor
)

logger = logging.getLogger(__name__)

class ThreatResponseService:
    """Service for automated threat response and incident management"""
    
    def __init__(self):
        self.response_active = False
        self.response_thread = None
        self.check_interval = 30  # seconds
        
    def start_response_service(self):
        """Start the automated threat response service"""
        if not self.response_active:
            self.response_active = True
            self.response_thread = threading.Thread(target=self._response_loop, daemon=True)
            self.response_thread.start()
            logger.info("Automated threat response service started")
    
    def stop_response_service(self):
        """Stop the automated threat response service"""
        self.response_active = False
        if self.response_thread:
            self.response_thread.join(timeout=10)
        logger.info("Automated threat response service stopped")
    
    def _response_loop(self):
        """Main response monitoring loop"""
        while self.response_active:
            try:
                self._check_for_triggers()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Error in response loop: {e}")
                time.sleep(self.check_interval)
    
    def _check_for_triggers(self):
        """Check for response triggers and execute playbooks"""
        active_playbooks = ThreatResponsePlaybook.objects.filter(
            is_active=True,
            auto_execute=True
        )
        
        for playbook in active_playbooks:
            try:
                if self._evaluate_trigger(playbook):
                    self._execute_playbook(playbook)
            except Exception as e:
                logger.error(f"Error evaluating trigger for playbook {playbook.name}: {e}")
    
    def _evaluate_trigger(self, playbook: ThreatResponsePlaybook) -> bool:
        """Evaluate if a playbook trigger condition is met"""
        trigger_type = playbook.trigger_type
        conditions = playbook.trigger_conditions
        
        if trigger_type == 'ioc_match':
            return self._check_ioc_match_trigger(conditions)
        elif trigger_type == 'severity_threshold':
            return self._check_severity_threshold_trigger(conditions)
        elif trigger_type == 'threat_type':
            return self._check_threat_type_trigger(conditions)
        elif trigger_type == 'actor_match':
            return self._check_actor_match_trigger(conditions)
        
        return False
    
    def _check_ioc_match_trigger(self, conditions: Dict) -> bool:
        """Check for IOC match triggers"""
        time_window = conditions.get('time_window', 300)  # 5 minutes default
        match_count = conditions.get('match_count', 1)
        severity_levels = conditions.get('severity_levels', ['critical', 'high'])
        
        since = timezone.now() - timedelta(seconds=time_window)
        
        matches = ThreatMatch.objects.filter(
            first_seen__gte=since,
            status='detected',
            ioc__severity__in=severity_levels
        ).count()
        
        return matches >= match_count
    
    def _check_severity_threshold_trigger(self, conditions: Dict) -> bool:
        """Check for severity threshold triggers"""
        time_window = conditions.get('time_window', 300)
        critical_count = conditions.get('critical_count', 5)
        high_count = conditions.get('high_count', 10)
        
        since = timezone.now() - timedelta(seconds=time_window)
        
        critical_matches = ThreatMatch.objects.filter(
            first_seen__gte=since,
            ioc__severity='critical',
            status='detected'
        ).count()
        
        high_matches = ThreatMatch.objects.filter(
            first_seen__gte=since,
            ioc__severity='high',
            status='detected'
        ).count()
        
        return critical_matches >= critical_count or high_matches >= high_count
    
    def _check_threat_type_trigger(self, conditions: Dict) -> bool:
        """Check for specific threat type triggers"""
        threat_types = conditions.get('threat_types', [])
        time_window = conditions.get('time_window', 300)
        match_count = conditions.get('match_count', 1)
        
        since = timezone.now() - timedelta(seconds=time_window)
        
        matches = ThreatMatch.objects.filter(
            first_seen__gte=since,
            ioc__threat_type__in=threat_types,
            status='detected'
        ).count()
        
        return matches >= match_count
    
    def _check_actor_match_trigger(self, conditions: Dict) -> bool:
        """Check for threat actor match triggers"""
        actor_names = conditions.get('actor_names', [])
        time_window = conditions.get('time_window', 300)
        
        since = timezone.now() - timedelta(seconds=time_window)
        
        # Check for IOCs associated with specific threat actors
        actor_iocs = IndicatorOfCompromise.objects.filter(
            context__threat_actor__in=actor_names
        )
        
        matches = ThreatMatch.objects.filter(
            first_seen__gte=since,
            ioc__in=actor_iocs,
            status='detected'
        ).count()
        
        return matches > 0
    
    def _execute_playbook(self, playbook: ThreatResponsePlaybook):
        """Execute a threat response playbook"""
        try:
            # Create execution record
            execution = ThreatResponseExecution.objects.create(
                playbook=playbook,
                trigger_event=self._get_trigger_event(playbook),
                status='running'
            )
            
            logger.info(f"Executing playbook: {playbook.name}")
            
            # Execute actions
            results = {}
            executed_actions = []
            
            for action in playbook.actions:
                try:
                    result = self._execute_action(action, execution)
                    results[action.get('name', 'unknown')] = result
                    executed_actions.append(action)
                except Exception as e:
                    logger.error(f"Error executing action {action.get('name')}: {e}")
                    execution.errors += f"Action {action.get('name')} failed: {e}\n"
            
            # Update execution record
            execution.status = 'completed'
            execution.completed_at = timezone.now()
            execution.executed_actions = executed_actions
            execution.results = results
            execution.save()
            
            # Update playbook statistics
            playbook.execution_count += 1
            playbook.last_executed = timezone.now()
            playbook.save()
            
            logger.info(f"Playbook {playbook.name} executed successfully")
            
        except Exception as e:
            logger.error(f"Error executing playbook {playbook.name}: {e}")
            if 'execution' in locals():
                execution.status = 'failed'
                execution.errors = str(e)
                execution.completed_at = timezone.now()
                execution.save()
    
    def _get_trigger_event(self, playbook: ThreatResponsePlaybook) -> Dict:
        """Get the current trigger event details"""
        return {
            'timestamp': timezone.now().isoformat(),
            'trigger_type': playbook.trigger_type,
            'conditions': playbook.trigger_conditions,
            'playbook_id': playbook.id,
            'playbook_name': playbook.name
        }
    
    def _execute_action(self, action: Dict, execution: ThreatResponseExecution) -> Dict:
        """Execute a specific response action"""
        action_type = action.get('type')
        action_params = action.get('parameters', {})
        
        if action_type == 'block_ip':
            return self._block_ip_action(action_params)
        elif action_type == 'quarantine_host':
            return self._quarantine_host_action(action_params)
        elif action_type == 'create_alert':
            return self._create_alert_action(action_params)
        elif action_type == 'notify_analysts':
            return self._notify_analysts_action(action_params)
        elif action_type == 'update_firewall':
            return self._update_firewall_action(action_params)
        elif action_type == 'isolate_network':
            return self._isolate_network_action(action_params)
        elif action_type == 'collect_evidence':
            return self._collect_evidence_action(action_params)
        elif action_type == 'run_script':
            return self._run_script_action(action_params)
        else:
            raise ValueError(f"Unknown action type: {action_type}")
    
    def _block_ip_action(self, params: Dict) -> Dict:
        """Block IP address action"""
        ip_address = params.get('ip_address')
        duration = params.get('duration', 3600)  # 1 hour default
        
        # Simulate IP blocking (in production, integrate with firewall/network equipment)
        logger.info(f"Blocking IP address: {ip_address} for {duration} seconds")
        
        return {
            'action': 'block_ip',
            'ip_address': ip_address,
            'duration': duration,
            'status': 'success',
            'timestamp': timezone.now().isoformat()
        }
    
    def _quarantine_host_action(self, params: Dict) -> Dict:
        """Quarantine host action"""
        hostname = params.get('hostname')
        ip_address = params.get('ip_address')
        
        logger.info(f"Quarantining host: {hostname} ({ip_address})")
        
        return {
            'action': 'quarantine_host',
            'hostname': hostname,
            'ip_address': ip_address,
            'status': 'success',
            'timestamp': timezone.now().isoformat()
        }
    
    def _create_alert_action(self, params: Dict) -> Dict:
        """Create system alert action"""
        title = params.get('title', 'Automated Threat Response Alert')
        message = params.get('message', 'Automated response action triggered')
        severity = params.get('severity', 'high')
        
        # Create alert in infrastructure system
        try:
            from infrastructure.models import SystemAlert, InfrastructureComponent
            
            # Find or create a generic component for threat response
            component, created = InfrastructureComponent.objects.get_or_create(
                name='Threat Response System',
                defaults={
                    'component_type': 'application',
                    'description': 'Automated threat response system'
                }
            )
            
            alert = SystemAlert.objects.create(
                component=component,
                alert_type='security',
                severity=severity,
                title=title,
                message=message
            )
            
            return {
                'action': 'create_alert',
                'alert_id': alert.id,
                'title': title,
                'severity': severity,
                'status': 'success',
                'timestamp': timezone.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            return {
                'action': 'create_alert',
                'status': 'failed',
                'error': str(e),
                'timestamp': timezone.now().isoformat()
            }
    
    def _notify_analysts_action(self, params: Dict) -> Dict:
        """Notify security analysts action"""
        message = params.get('message', 'Threat detected - immediate attention required')
        urgency = params.get('urgency', 'high')
        analysts = params.get('analysts', [])
        
        logger.info(f"Notifying analysts: {message} (Urgency: {urgency})")
        
        # In production, integrate with notification systems (email, Slack, etc.)
        
        return {
            'action': 'notify_analysts',
            'message': message,
            'urgency': urgency,
            'analysts_notified': len(analysts),
            'status': 'success',
            'timestamp': timezone.now().isoformat()
        }
    
    def _update_firewall_action(self, params: Dict) -> Dict:
        """Update firewall rules action"""
        rule_type = params.get('rule_type', 'block')
        target = params.get('target')
        rule_name = params.get('rule_name', f"Auto-{rule_type}-{int(time.time())}")
        
        logger.info(f"Updating firewall: {rule_type} rule for {target}")
        
        return {
            'action': 'update_firewall',
            'rule_type': rule_type,
            'target': target,
            'rule_name': rule_name,
            'status': 'success',
            'timestamp': timezone.now().isoformat()
        }
    
    def _isolate_network_action(self, params: Dict) -> Dict:
        """Network isolation action"""
        network_segment = params.get('network_segment')
        isolation_level = params.get('isolation_level', 'full')
        
        logger.info(f"Isolating network segment: {network_segment} (Level: {isolation_level})")
        
        return {
            'action': 'isolate_network',
            'network_segment': network_segment,
            'isolation_level': isolation_level,
            'status': 'success',
            'timestamp': timezone.now().isoformat()
        }
    
    def _collect_evidence_action(self, params: Dict) -> Dict:
        """Evidence collection action"""
        evidence_types = params.get('evidence_types', ['network_logs', 'system_logs'])
        target_hosts = params.get('target_hosts', [])
        
        logger.info(f"Collecting evidence: {evidence_types} from {len(target_hosts)} hosts")
        
        return {
            'action': 'collect_evidence',
            'evidence_types': evidence_types,
            'target_hosts': len(target_hosts),
            'status': 'success',
            'timestamp': timezone.now().isoformat()
        }
    
    def _run_script_action(self, params: Dict) -> Dict:
        """Run custom script action"""
        script_name = params.get('script_name')
        script_args = params.get('script_args', [])
        
        logger.info(f"Running script: {script_name} with args: {script_args}")
        
        # In production, implement secure script execution
        
        return {
            'action': 'run_script',
            'script_name': script_name,
            'script_args': script_args,
            'status': 'success',
            'timestamp': timezone.now().isoformat()
        }
    
    def manual_execute_playbook(self, playbook_id: int, user: User, trigger_event: Dict = None) -> ThreatResponseExecution:
        """Manually execute a playbook"""
        try:
            playbook = ThreatResponsePlaybook.objects.get(id=playbook_id)
            
            # Create execution record
            execution = ThreatResponseExecution.objects.create(
                playbook=playbook,
                trigger_event=trigger_event or {'manual_execution': True, 'user': user.username},
                status='running',
                executed_by=user
            )
            
            logger.info(f"Manually executing playbook: {playbook.name} by {user.username}")
            
            # Execute actions
            results = {}
            executed_actions = []
            
            for action in playbook.actions:
                try:
                    result = self._execute_action(action, execution)
                    results[action.get('name', 'unknown')] = result
                    executed_actions.append(action)
                except Exception as e:
                    logger.error(f"Error executing action {action.get('name')}: {e}")
                    execution.errors += f"Action {action.get('name')} failed: {e}\n"
            
            # Update execution record
            execution.status = 'completed'
            execution.completed_at = timezone.now()
            execution.executed_actions = executed_actions
            execution.results = results
            execution.save()
            
            # Update playbook statistics
            playbook.execution_count += 1
            playbook.last_executed = timezone.now()
            playbook.save()
            
            return execution
            
        except Exception as e:
            logger.error(f"Error manually executing playbook: {e}")
            if 'execution' in locals():
                execution.status = 'failed'
                execution.errors = str(e)
                execution.completed_at = timezone.now()
                execution.save()
                return execution
            raise
    
    def get_response_statistics(self) -> Dict:
        """Get threat response system statistics"""
        try:
            total_playbooks = ThreatResponsePlaybook.objects.count()
            active_playbooks = ThreatResponsePlaybook.objects.filter(is_active=True).count()
            auto_playbooks = ThreatResponsePlaybook.objects.filter(auto_execute=True).count()
            
            # Recent executions
            recent_executions = ThreatResponseExecution.objects.filter(
                started_at__gte=timezone.now() - timedelta(hours=24)
            ).count()
            
            successful_executions = ThreatResponseExecution.objects.filter(
                started_at__gte=timezone.now() - timedelta(hours=24),
                status='completed'
            ).count()
            
            failed_executions = ThreatResponseExecution.objects.filter(
                started_at__gte=timezone.now() - timedelta(hours=24),
                status='failed'
            ).count()
            
            return {
                'total_playbooks': total_playbooks,
                'active_playbooks': active_playbooks,
                'auto_playbooks': auto_playbooks,
                'recent_executions_24h': recent_executions,
                'successful_executions_24h': successful_executions,
                'failed_executions_24h': failed_executions,
                'success_rate': (successful_executions / recent_executions * 100) if recent_executions > 0 else 0,
                'service_status': 'active' if self.response_active else 'inactive',
                'last_updated': timezone.now()
            }
            
        except Exception as e:
            logger.error(f"Error getting response statistics: {e}")
            return {}

# Global instance
threat_response_service = ThreatResponseService()