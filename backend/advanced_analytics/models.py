from django.db import models
from django.utils import timezone
from django.db.models import JSONField


class HuntJob(models.Model):
    """Represents an unsupervised threat hunting job."""
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    query = JSONField(null=True, blank=True)
    status = models.CharField(max_length=50, default='pending')
    results = JSONField(null=True, blank=True)

    def __str__(self):
        return f"Hunt: {self.name} ({self.status})"


class AttackSimulation(models.Model):
    """Defines a red-team simulation scenario (MITRE ATT&CK steps)."""
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    scenario = JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_run = models.DateTimeField(null=True, blank=True)
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class TamperProofLog(models.Model):
    """A log entry with a Merkle hash chain reference for tamper-proofing."""
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    entry = JSONField()
    merkle_hash = models.CharField(max_length=512)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"Log @ {self.timestamp}"
