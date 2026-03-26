from pydantic import BaseModel
from typing import Optional, List

class ReasoningRequest(BaseModel):
    predicted_class: str
    confidence: float
    source_ip: str = "0.0.0.0"
    dest_ip: str = "127.0.0.1"
    protocol: str = "TCP"
    port: int = 80
    threat_level: Optional[str] = "HIGH"

class ReasoningResponse(BaseModel):
    threat_summary: str
    recommendations: List[str]
    risk_level: str
    cve_context_used: str