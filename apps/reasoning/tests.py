from django.test import TestCase, Client
from django.urls import reverse
import json

class ReasoningViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse('reason_threat')

    def test_reasoning_fallback_logic(self):
        """Verify that the view returns expert analysis even without Ollama (fallback)."""
        payload = {"predicted_class": "dos", "confidence": 0.95}
        response = self.client.post(
            self.url, 
            data=json.dumps(payload), 
            content_type='application/json'
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(len(data['threat_summary']) > 0)