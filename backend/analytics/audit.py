from django.db import models
from django.conf import settings
from django.utils import timezone


class AuditLog(models.Model):
    """Immutable audit log for compliance and forensic review."""
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    action = models.CharField(max_length=100)
    object_type = models.CharField(max_length=200)
    object_id = models.CharField(max_length=200, null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    details = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Audit Log'

    def __str__(self):
        return f"{self.action} by {self.actor} at {self.timestamp}"
