from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import AnomalyDetectionModel, BehavioralProfile, AnomalyDetection
from .serializers import AnomalyDetectionModelSerializer, BehavioralProfileSerializer, AnomalyDetectionSerializer
from .ml_services import ml_threat_detector


class AnomalyModelViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AnomalyDetectionModel.objects.all().order_by('-last_trained')
    serializer_class = AnomalyDetectionModelSerializer

    @action(detail=True, methods=['post'])
    def detect(self, request, pk=None):
        """Run anomaly detection using the specified model. Expects CSV/JSON payload or dataset reference."""
        model_id = pk
        # For safety: accept optional data param as list of dicts
        data = request.data.get('data', None)
        if data is None:
            return Response({'error': 'No data provided'}, status=status.HTTP_400_BAD_REQUEST)
        import pandas as pd
        try:
            df = pd.DataFrame(data)
            anomalies = ml_threat_detector.detect_anomalies(int(model_id), df)
            return Response({'anomalies': anomalies})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TrainingViewSet(viewsets.ViewSet):
    """Simple viewset to trigger model training"""

    def create(self, request):
        # POST { "dataset_id": 1, "type": "isolation_forest", "contamination": 0.1 }
        dataset_id = request.data.get('dataset_id')
        model_type = request.data.get('type', 'isolation_forest')
        if not dataset_id:
            return Response({'error': 'dataset_id required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            if model_type == 'isolation_forest':
                contamination = float(request.data.get('contamination', 0.1))
                model = ml_threat_detector.train_isolation_forest(int(dataset_id), contamination=contamination)
            else:
                model = ml_threat_detector.train_lstm_autoencoder(int(dataset_id), sequence_length=int(request.data.get('sequence_length', 10)))
            return Response({'model_id': model.id})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class BehavioralViewSet(viewsets.ViewSet):
    """Expose behavioral analysis endpoints"""

    @action(detail=False, methods=['post'])
    def analyze(self, request):
        entity_type = request.data.get('entity_type')
        entity_id = request.data.get('entity_id')
        if not entity_type or not entity_id:
            return Response({'error': 'entity_type and entity_id required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            result = ml_threat_detector.analyze_behavioral_patterns(entity_type, entity_id)
            return Response(result)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
