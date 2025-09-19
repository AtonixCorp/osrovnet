from django.contrib import admin
from .models import PQCKey


@admin.register(PQCKey)
class PQCKeyAdmin(admin.ModelAdmin):
    list_display = ('id', 'owner', 'name', 'algorithm', 'private_key_retention', 'created_at')
    readonly_fields = ('public_key',)
