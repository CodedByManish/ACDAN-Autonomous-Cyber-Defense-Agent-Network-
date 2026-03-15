from ninja import Router, Schema
from .services import reasoning_service
import logging

logger = logging.getLogger(__name__)
router = Router()

class ReasoningRequest(Schema):
    predicted_class: str
    confidence: float
    threat_level: str

@router.post("/reason")
def reason_threat(request, data: ReasoningRequest):
    try:
        analysis = reasoning_service.generate_analysis(data.dict())
        return analysis
    except Exception as e:
        logger.error(f"Reasoning Error: {str(e)}")
        return {"error": str(e), "threat_summary": "Failed to generate AI analysis."}