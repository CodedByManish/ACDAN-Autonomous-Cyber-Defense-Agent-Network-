from pydantic import BaseModel
from typing import Dict, Any

class ResponseRequest(BaseModel):
    predicted_class: str
    risk_level: str

class ResponseResponse(BaseModel):
    attack_identified: str
    recommended_action: str
    confidence_score: float
    rationale: str
    impact_on_system: float