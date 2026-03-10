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
        """Convert predicted class to threat level."""
        mapping = {
            "normal": "LOW",
            "probe": "MEDIUM",
            "dos": "HIGH",
            "r2l": "CRITICAL",
            "u2r": "CRITICAL",
        }
        return mapping.get(attack_class.lower(), "UNKNOWN")

    def get_class_explanation(self, attack_class: str) -> Dict:
        """Return explanation for predicted attack class."""

        explanations = {
            "normal": {
                "description": "Normal network traffic",
                "risk": "No threat detected",
                "indicators": "Standard communication patterns",
            },
            "probe": {
                "description": "Reconnaissance activity",
                "risk": "Network scanning for vulnerabilities",
                "indicators": "Port scans, service enumeration",
            },
            "dos": {
                "description": "Denial of Service attack",
                "risk": "Service disruption",
                "indicators": "High traffic volume, resource exhaustion",
            },
            "r2l": {
                "description": "Remote to Local intrusion",
                "risk": "Unauthorized system access",
                "indicators": "Repeated login attempts, protocol abuse",
            },
            "u2r": {
                "description": "User to Root escalation",
                "risk": "Privilege escalation",
                "indicators": "Suspicious system calls, permission bypass",
            },
        }

        return explanations.get(
            attack_class.lower(),
            {"description": "Unknown attack", "risk": "Undefined"},
        )