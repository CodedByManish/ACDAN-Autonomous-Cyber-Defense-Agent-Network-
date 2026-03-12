"""
Inference engine for anomaly detection.
Handles real-time predictions using trained models.
"""

import sys
import json
from pathlib import Path
from typing import Dict, List

import torch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from .model import SimpleDNNAnomalyDetector, TransformerAnomalyDetector
from .preprocessor import DataPreprocessor


class AnomalyDetectionInference:
    """Engine for running real-time anomaly detection."""

    def __init__(self, models_path: str = "./data/models", device: str | None = None):
        self.models_path = Path(models_path)
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")

        self.model = None
        self.metadata = None
        self.model_type = "dnn"

        self.preprocessor = DataPreprocessor()

        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Load model, metadata, and preprocessing artifacts."""

        # Metadata
        metadata_path = self.models_path / "metadata.json"
        with open(metadata_path, "r") as f:
            self.metadata = json.load(f)

        # Preprocessor
        preprocessor_path = self.models_path / "preprocessor.pkl"
        self.preprocessor.load_preprocessor(str(preprocessor_path))

        # Model path
        model_path = self.models_path / "best_model.pt"
        if not model_path.exists():
            model_path = self.models_path / "final_model.pt"

        # Initialize model
        if self.model_type == "transformer":
            self.model = TransformerAnomalyDetector(
                input_size=self.metadata["n_features"],
                num_classes=self.metadata["n_classes"],
            )
        else:
            self.model = SimpleDNNAnomalyDetector(
                input_size=self.metadata["n_features"],
                num_classes=self.metadata["n_classes"],
            )

        # Load weights
        self.model.load_state_dict(torch.load(model_path, map_location=self.device))
        self.model.to(self.device)
        self.model.eval()

        print(f"Model loaded from {model_path}")

    def predict_single(self, features: Dict[str, float]) -> Dict:
        """Run prediction on a single sample."""

        X = self.preprocessor.preprocess_inference_data(features)
        X = torch.FloatTensor(X).unsqueeze(0).to(self.device)

        with torch.no_grad():
            logits, probabilities = self.model(X)

        pred_idx = torch.argmax(logits, dim=1).item()
        pred_class = self.metadata["classes"][pred_idx]
        confidence = probabilities[0, pred_idx].item()

        return {
            "predicted_class": pred_class,
            "confidence": confidence,
            "threat_level": self._map_threat_level(pred_class),
            "all_probabilities": {
                cls: prob.item()
                for cls, prob in zip(self.metadata["classes"], probabilities[0])
            },
        }

    def predict_batch(self, batch_features: List[Dict]) -> List[Dict]:
        """Run predictions on multiple samples."""
        return [self.predict_single(features) for features in batch_features]

    def _map_threat_level(self, attack_class: str) -> str:
        """
        Convert CIC-IDS-2017 predicted classes to threat levels.
        """
        # Normalize the class name to handle case sensitivity and special characters
        cls = attack_class.upper().strip()
        
        if cls == 'BENIGN':
            return "LOW"
        
        if 'PORTSCAN' in cls:
            return "MEDIUM"
        
        # High threats (DoS / Brute Force / Bot / SQL Injection)
        if any(x in cls for x in ['DOS', 'DDOS', 'PATATOR', 'BRUTE FORCE']):
            return "HIGH"
        
        # Critical threats (Infiltration / Web Attacks / Heartbleed)
        if any(x in cls for x in ['INFILTRATION', 'WEB ATTACK', 'HEARTBLEED', 'BOT', 'SQL']):
            return "CRITICAL"
        
        return "UNKNOWN"

    def get_class_explanation(self, attack_class: str) -> Dict:
        """
        Return detailed explanations based on CIC-IDS-2017 labels.
        """
        cls = attack_class.upper().strip()
        
        explanations = {
            "BENIGN": {
                "description": "Legitimate network traffic.",
                "risk": "Minimal",
                "indicators": "Standard behavior patterns."
            },
            "DDOS": {
                "description": "Distributed Denial of Service.",
                "risk": "Total service unavailability.",
                "indicators": "Massive volumetric traffic from multiple sources."
            },
            "DOS HULK": {
                "description": "DoS HTTP Unbearable Load King.",
                "risk": "Web server resource exhaustion.",
                "indicators": "High volume of unique HTTP requests."
            },
            "PORTSCAN": {
                "description": "Port scanning/Reconnaissance.",
                "risk": "Information gathering for future attacks.",
                "indicators": "Sequential attempts to connect to multiple ports."
            },
            "INFILTRATION": {
                "description": "Internal network penetration.",
                "risk": "Data exfiltration and lateral movement.",
                "indicators": "Exploiting vulnerable internal software."
            }
        }

        # Return specific explanation or a generic one for attacks not listed above
        if cls in explanations:
            return explanations[cls]
        
        return {
            "description": f"Detected {attack_class} activity.",
            "risk": "Potential security breach.",
            "indicators": "Anomalous traffic features detected by AI."
        }