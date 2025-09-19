from django.db import models
from django.conf import settings


class PQCKey(models.Model):
    """Metadata record for generated post-quantum keys.

    The app intentionally stores metadata and public key material. Storing
    private key material is optional and disabled by default for security.
    """

    OWNER_RETAIN_CHOICES = (
        ('none', 'Do not store private key'),
        ('encrypted', 'Store encrypted (admin only)'),
    )

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='pqc_keys'
    )
    name = models.CharField(max_length=150)
    algorithm = models.CharField(max_length=128)
    public_key = models.BinaryField(null=True, blank=True)
    private_key_encrypted = models.BinaryField(null=True, blank=True)
    private_key_retention = models.CharField(
        max_length=16, choices=OWNER_RETAIN_CHOICES, default='none'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.owner} - {self.name} ({self.algorithm})"
