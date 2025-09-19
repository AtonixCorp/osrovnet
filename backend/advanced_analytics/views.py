from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import HuntJob, AttackSimulation, TamperProofLog
from .serializers import HuntJobSerializer, AttackSimulationSerializer, TamperProofLogSerializer
from django.utils import timezone
import hashlib
import json


class HuntJobViewSet(viewsets.ModelViewSet):
    queryset = HuntJob.objects.all().order_by('-created_at')
    serializer_class = HuntJobSerializer

    @action(detail=True, methods=['post'])
    def run(self, request, pk=None):
        job = self.get_object()
        # placeholder: run unsupervised hunter - in real life this would enqueue a job
        job.status = 'running'
        job.save()
        # fake result
        job.results = {'hits': []}
        job.status = 'completed'
        job.save()
        return Response({'status': 'completed', 'results': job.results})


class AttackSimulationViewSet(viewsets.ModelViewSet):
    queryset = AttackSimulation.objects.all().order_by('-created_at')
    serializer_class = AttackSimulationSerializer

    @action(detail=True, methods=['post'])
    def run(self, request, pk=None):
        sim = self.get_object()
        sim.last_run = timezone.now()
        sim.save()
        # placeholder: simulate steps and return summary
        return Response({'status': 'completed', 'last_run': sim.last_run})


class TamperProofLogViewSet(viewsets.ModelViewSet):
    queryset = TamperProofLog.objects.all().order_by('-timestamp')
    serializer_class = TamperProofLogSerializer

    def perform_create(self, serializer):
        entry = serializer.validated_data.get('entry')
        # compute a merkle-like hash by hashing JSON string (placeholder)
        h = hashlib.sha256(json.dumps(entry, sort_keys=True).encode('utf-8')).hexdigest()
        serializer.save(merkle_hash=h)
