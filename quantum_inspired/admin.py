from django.contrib import admin
from .models import SimulationJob


@admin.register(SimulationJob)
class SimulationJobAdmin(admin.ModelAdmin):
    list_display = ('id', 'owner', 'technique', 'name', 'created_at', 'completed_at')
    readonly_fields = ('result',)
