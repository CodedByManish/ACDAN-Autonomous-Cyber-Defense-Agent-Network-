"""
Inference engine for anomaly detection.
Used for real-time predictions.
"""

import torch
import json
import os
from typing import Dict, Tuple, List
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from agents.anomaly_detection.model import SimpleDNNAnomalyDetector, TransformerAnomalyDetector
from agents.anomaly_detection.preprocessor import DataPreprocessor


class AnomalyDetectionInference:
    """Real-time anomaly detection inference engine."""
    
    def __init__(self, models_path: str = "./data/models", device: str = None):
        """
        Initialize inference engine.
        
        Args:
            models_path: Path to saved models
            device: "cuda" or "cpu"
        """
        self.models_path = Path(models_path)
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        
        self.model = None
        self.preprocessor = DataPreprocessor()
        self.metadata = None
        self.model_type = None
        
        self.load_artifacts()
    
    def load_artifacts(self) -> None:
        """Load model, preprocessor, and metadata."""
        # Load metadata
        metadata_path = self.models_path / "metadata.json"
        with open(metadata_path, 'r') as f:
            self.metadata = json.load(f)
        
        print(f"Loaded metadata: {self.metadata['n_features']} features, {self.metadata['n_classes']} classes")
        
        # Load preprocessor
        preprocessor_path = self.models_path / "preprocessor.pkl"
        self.preprocessor.load_preprocessor(str(preprocessor_path))
        
        # Load model
        model_path = self.models_path / "best_model.pt"
        if not model_path.exists():
            model_path = self.models_path / "final_model.pt"
        
        # Detect model type (you could store this in metadata too)
        self.model_type = "dnn"  # Default
        
        if self.model_type == "transformer":
            self.model = TransformerAnomalyDetector(
                input_size=self.metadata['n_features'],
                num_classes=self.metadata['n_classes']
            )
        else:
            self.model = SimpleDNNAnomalyDetector(
                input_size=self.metadata['n_features'],
                num_classes=self.metadata['n_classes']
            )
        
        self.model.load_state_dict(torch.load(model_path, map_location=self.device))
        self.model.to(self.device)
        self.model.eval()
        
        print(f"Model loaded from {model_path}")
    
    def predict_single(self, features: Dict[str, float]) -> Dict[str, any]:
        """
        Predict on single sample.
        
        Args:
            features: Dictionary of feature values
            
        Returns:
            Dictionary with prediction, confidence, and threat level
        """
        # Preprocess
        X = self.preprocessor.preprocess_inference_data(features)
        X = torch.FloatTensor(X).unsqueeze(0).to(self.device)
        
        # Predict
        with torch.no_grad():
            logits, probabilities = self.model(X)
        
        pred_class_idx = torch.argmax(logits, dim=1).item()
        pred_class = self.metadata['classes'][pred_class_idx]
        confidence = probabilities[0, pred_class_idx].item()
        
        # Determine threat level
        threat_level = self._get_threat_level(pred_class)
        
        return {
            'predicted_class': pred_class,
            'confidence': confidence,
            'threat_level': threat_level,
            'all_probabilities': {
                cls: prob.item()
                for cls, prob in zip(self.metadata['classes'], probabilities[0])
            }
        }
    
    def predict_batch(self, batch_features: List[Dict]) -> List[Dict]:
        """Predict on batch of samples."""
        results = []
        for features in batch_features:
            results.append(self.predict_single(features))
        return results
    
    def _get_threat_level(self, attack_class: str) -> str:
        """Map attack class to threat level."""
        threat_mapping = {
            'normal': 'LOW',
            'probe': 'MEDIUM',
            'dos': 'HIGH',
            'r2l': 'CRITICAL',
            'u2r': 'CRITICAL',
        }
        return threat_mapping.get(attack_class.lower(), 'UNKNOWN')
    
    def get_class_explanation(self, attack_class: str) -> Dict:
        """Provide explanation for attack class."""
        explanations = {
            'normal': {
                'description': 'Normal network traffic',
                'risk': 'No risk detected',
                'indicators': 'Standard communication patterns'
            },
            'probe': {
                'description': 'Reconnaissance attack',
                'risk': 'Attacker scanning network for vulnerabilities',
                'indicators': 'Unusual port scanning, service enumeration'
            },
            'dos': {
                'description': 'Denial of Service attack',
                'risk': 'Service disruption',
                'indicators': 'Excessive traffic, resource depletion'
            },
            'r2l': {
                'description': 'Remote to Local attack',
                'risk': 'Unauthorized remote access',
                'indicators': 'Invalid login attempts, protocol exploitation'
            },
            'u2r': {
                'description': 'User to Root attack',
                'risk': 'Privilege escalation',
                'indicators': 'Unusual system calls, permission bypasses'
            }
        }
        return explanations.get(attack_class.lower(), {'description': 'Unknown attack', 'risk': 'Undefined'})