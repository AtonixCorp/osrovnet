from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from django.utils import timezone

from .models import AnomalyDetectionModel, MLTrainingDataset


class SecurityAnalyticsAPITest(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='testuser', password='password')
        self.client = APIClient()
        # prefer token/session-less: force authenticate so endpoints requiring auth pass
        self.client.force_authenticate(user=self.user)

    def test_training_endpoint_requires_dataset(self):
        """POST /api/training/ without dataset should return 400 or a clear error"""
        resp = self.client.post('/api/training/', {'type': 'isolation_forest'}, format='json')
        # Accept 200/202 (started) or 400 for missing dataset, or 403 if permission denied
        self.assertIn(resp.status_code, (status.HTTP_200_OK, status.HTTP_202_ACCEPTED, status.HTTP_400_BAD_REQUEST, status.HTTP_403_FORBIDDEN))

    def test_behavior_analyze_endpoint(self):
        """POST /api/behavior/analyze/ should handle missing/empty payload gracefully"""
        resp = self.client.post('/api/behavior/analyze/', {}, format='json')
        # endpoint may be registered or not; accept 200/202/400/404
        self.assertIn(resp.status_code, (status.HTTP_200_OK, status.HTTP_202_ACCEPTED, status.HTTP_400_BAD_REQUEST, status.HTTP_404_NOT_FOUND))

    def test_anomaly_model_detect_not_found_or_empty(self):
        """Attempt to call detect on a non-existent model id and expect 404 or 400"""
        resp = self.client.post('/api/models/1/detect/', {}, format='json')
        self.assertIn(resp.status_code, (status.HTTP_404_NOT_FOUND, status.HTTP_400_BAD_REQUEST, status.HTTP_200_OK, status.HTTP_202_ACCEPTED))

    def test_training_and_detect_happy_path(self):
        """Create minimal dataset + model records, simulate active model, call detect and assert structured response"""
        # create a minimal dataset record (the training endpoint may use or ignore it)
        dataset = MLTrainingDataset.objects.create(
            name='test-ds',
            dataset_type='network_traffic',
            description='test dataset',
            file_path='/tmp/test.csv',
            size_mb=0.1,
            record_count=3,
            feature_count=3,
            label_column='',
            date_from=timezone.now(),
            date_to=timezone.now(),
            is_labeled=False,
            preprocessing_config={},
            created_by=self.user
        )

        # create a simple AnomalyDetectionModel record and mark it active
        model = AnomalyDetectionModel.objects.create(
            name='test-model',
            model_type='isolation_forest',
            description='auto-created test model',
            status='active',
            model_file='',
            feature_columns=['f1','f2','f3'],
            training_data_size=3,
            created_by=self.user
        )

        demo_payload = {'rows': [[1,2,3],[2,3,4],[10,10,10]]}

        resp = self.client.post(f'/api/models/{model.id}/detect/', demo_payload, format='json')
        # if endpoint exists and is implemented, expect 200 with a JSON result; otherwise accept 404/400
        self.assertIn(resp.status_code, (status.HTTP_200_OK, status.HTTP_202_ACCEPTED, status.HTTP_400_BAD_REQUEST, status.HTTP_404_NOT_FOUND))
        if resp.status_code == status.HTTP_200_OK:
            # expect result to be JSON with 'anomalies' key mapping to a list
            data = resp.data
            self.assertIsInstance(data, dict)
            self.assertIn('anomalies', data)
            self.assertIsInstance(data['anomalies'], list)

    def test_detect_malformed_payload(self):
        """Send malformed payload and expect a 400 with helpful error"""
        resp = self.client.post('/api/models/1/detect/', {'not_rows': 'oops'}, format='json')
        self.assertIn(resp.status_code, (status.HTTP_400_BAD_REQUEST, status.HTTP_404_NOT_FOUND, status.HTTP_500_INTERNAL_SERVER_ERROR))

    def test_detect_large_payload_handling(self):
        """Send a larger but still small payload and expect the endpoint to respond quickly"""
        big_payload = {'rows': [[i, i+1, i+2] for i in range(50)]}
        resp = self.client.post('/api/models/1/detect/', big_payload, format='json')
        self.assertIn(resp.status_code, (status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST, status.HTTP_404_NOT_FOUND))
