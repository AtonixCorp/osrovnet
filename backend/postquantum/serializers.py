from rest_framework import serializers
from .models import PQCKey


class PQCKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = PQCKey
        fields = ['id', 'owner', 'name', 'algorithm', 'public_key', 'private_key_retention', 'created_at']
        read_only_fields = ['id', 'owner', 'created_at']


class AlgorithmListSerializer(serializers.Serializer):
    name = serializers.CharField()
    description = serializers.CharField()
