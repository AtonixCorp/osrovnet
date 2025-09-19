from rest_framework import serializers
from .models import AnomalyDetectionModel, BehavioralProfile, AnomalyDetection


class AnomalyDetectionModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnomalyDetectionModel
        fields = '__all__'


class BehavioralProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = BehavioralProfile
        fields = '__all__'


class AnomalyDetectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnomalyDetection
        fields = '__all__'
