from ninja import Router, Schema
from typing import Optional, List
from .services import reasoning_service
import logging

logger = logging.getLogger(__name__)
router = Router()

class ReasoningRequest(Schema):
    predicted_class: str
    confidence: float
    threat_level: Optional[str] = "HIGH"

# Define a response schema to ensure Ninja sends back clean data
class ReasoningResponse(Schema):
    threat_summary: str
    recommendations: List[str]
    risk_level: str
    cve_context_used: str

@router.post("/reason") 
def reason_threat(request, data: ReasoningRequest):
    try:
        
        payload = data.dict()
        analysis = reasoning_service.generate_analysis(payload)
        return analysis
    except Exception as e:
        logger.error(f"Reasoning Error: {str(e)}")
        
        return {
            "threat_summary": "AI Reasoning failed.",
            "recommendations": ["Check logs"],
            "risk_level": "UNKNOWN",
            "cve_context_used": "Error"
        }