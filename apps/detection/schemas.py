# apps/detection/schemas.py
from ninja import Schema
from typing import Optional, Dict, Any

class IngestLogRequest(Schema):
    source_ip: str
    dest_ip: str
    protocol: str
    port: int
    duration: int
    # This allows you to pass the dictionary of 79 features
    features: Dict[str, float] 

class PredictionResponse(Schema):
    is_threat: bool
    threat_type: str
    confidence_score: float
    recommended_action: str
    metadata: Dict[str, Any] = {}