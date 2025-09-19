from django.apps import AppConfig


class SecurityAnalyticsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'security_analytics'
    verbose_name = 'Security Analytics & ML Threat Detection'
    
    def ready(self):
        import security_analytics.signals