from ninja import Schema
from typing import Dict, Optional, List, Any
from datetime import datetime

class PredictionResponse(Schema):
    predicted_class: str
    confidence: float
    threat_level: str
    all_probabilities: Dict[str, float]

class ThreatAnalysisRequest(Schema):
    attack_type: str
    confidence: float
    source_ip: str
    dest_ip: str
    protocol: str
    port: int