"""
Infrastructure app initialization
"""
from django.apps import AppConfig

class InfrastructureConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'infrastructure'
    verbose_name = 'Infrastructure Monitoring'
    
    def ready(self):
        """Initialize infrastructure monitoring when app is ready"""
        try:
            # Import and start health monitoring service
            from .health_service import health_monitoring_service
            health_monitoring_service.start_monitoring()
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to start health monitoring service: {e}")