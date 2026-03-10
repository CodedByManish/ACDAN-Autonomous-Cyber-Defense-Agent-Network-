from django.test import TestCase, Client
from django.urls import reverse
import json

class DetectionViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse('detect_threat')

    def test_detection_post_valid_data(self):
        """Test if the detection view handles valid packet data."""
        payload = {"protocol_type": "tcp", "src_bytes": 500}
        response = self.client.post(
            self.url, 
            data=json.dumps(payload), 
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('predicted_class', response.json())