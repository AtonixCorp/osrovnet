from django.db import models
from django.db.models import JSONField


class Metric(models.Model):
    """Time-series metric point for real-time dashboards."""
    name = models.CharField(max_length=200, db_index=True)
    timestamp = models.DateTimeField(db_index=True)
    value = models.FloatField()
    tags = JSONField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['name', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.name} @ {self.timestamp}: {self.value}"


class Event(models.Model):
    """Generic event store (alerts, user actions, system events)."""
    EVENT_TYPES = [
        ('alert', 'Alert'),
        ('user', 'User Activity'),
        ('system', 'System'),
        ('financial', 'Financial'),
        ('other', 'Other'),
    ]

    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    timestamp = models.DateTimeField(db_index=True)
    payload = JSONField()
    severity = models.CharField(max_length=20, null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.event_type} @ {self.timestamp}"


class ReportDefinition(models.Model):
    """Saved ad-hoc report definition metadata."""
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # stored as a JSON descriptor for the fields/filters/visualization
    definition = JSONField()

    def __str__(self):
        return self.name


class ScheduledReport(models.Model):
    report = models.ForeignKey(ReportDefinition, on_delete=models.CASCADE, related_name='schedules')
    cron = models.CharField(max_length=100, help_text='Cron expression or presets (daily/hourly)')
    recipients = JSONField(help_text='List of recipients (emails/webhooks)')
    last_run = models.DateTimeField(null=True, blank=True)
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return f"Schedule for {self.report.name} ({self.cron})"
