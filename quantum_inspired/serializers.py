from rest_framework import serializers
from .models import SimulationJob


class SimulationJobSerializer(serializers.ModelSerializer):
    class Meta:
        model = SimulationJob
        fields = ['id', 'owner', 'technique', 'name', 'params', 'result', 'created_at', 'completed_at']
        read_only_fields = ['id', 'owner', 'result', 'created_at', 'completed_at']


class TechniqueListSerializer(serializers.Serializer):
    key = serializers.CharField()
    description = serializers.CharField()
