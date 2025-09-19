from rest_framework import serializers
from .models import HuntJob, AttackSimulation, TamperProofLog


class HuntJobSerializer(serializers.ModelSerializer):
    class Meta:
        model = HuntJob
        fields = '__all__'


class AttackSimulationSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttackSimulation
        fields = '__all__'


class TamperProofLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = TamperProofLog
        fields = '__all__'
