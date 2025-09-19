from django.apps import AppConfig


class SiemConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'siem'
    verbose_name = 'Security Information and Event Management'
    
    def ready(self):
        import siem.signals