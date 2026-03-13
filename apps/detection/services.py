# apps/detection/services.py
from .ml_logic.inference import AnomalyDetectionInference
import os

class DetectionService:
    def __init__(self):

        # This will load the model weights (best_model.pt) on startup
        models_path = os.path.join(os.getcwd(), "data", "models")
        self.engine = AnomalyDetectionInference(models_path=models_path)

    def predict(self, features: dict):
        # calls predict_single method from inference.py
        return self.engine.predict_single(features)

detection_service = DetectionService()