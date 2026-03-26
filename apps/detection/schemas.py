from pydantic import BaseModel, Field
from typing import Dict, Any

class IngestLogRequest(BaseModel):
    source_ip: str
    dest_ip: str
    protocol: str
    port: int
    duration: int
    features: Dict[str, float]

class PredictionResponse(BaseModel):
    is_threat: bool
    threat_type: str
    confidence_score: float
    recommended_action: str
    metadata: Dict[str, Any] = {}