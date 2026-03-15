from ninja import Router, Schema
from .services import reasoning_service

router = Router()

class ReasoningRequest(Schema):
    predicted_class: str
    confidence: float
    threat_level: str

@router.post("/reason")
def reason_threat(request, data: ReasoningRequest):
    # Convert Schema to dict for the service
    analysis = reasoning_service.generate_analysis(data.dict())
    return analysis