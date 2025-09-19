from django.test import TestCase


class RegisterTestCase(TestCase):
    def test_register(self):
        data = {"username": "testreg2", "password": "password123", "email": "reg2@example.com"}
        resp = self.client.post('/api/auth/register/', data, content_type='application/json')
        # Expect 201 Created
        self.assertIn(resp.status_code, (200, 201), msg=f"Unexpected status: {resp.status_code} body: {resp.content}")
from django.test import TestCase

# Create your tests here.
