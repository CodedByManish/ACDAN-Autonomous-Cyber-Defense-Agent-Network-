from ninja import Router, Schema
from .services import response_service

router = Router()

class ResponseRequest(Schema):
    predicted_class: str
    risk_level: str

@router.post("/execute")
def execute_response(request, data: ResponseRequest):
    """
    Final Stage of ACDAN: Determines the best mitigation strategy using RL.
    """
    try:
        result = response_service.determine_action(
            predicted_class=data.predicted_class, 
            risk_level=data.risk_level
        )
        return result
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "recommended_action": "ALERT_ADMIN" # Fail-safe action
        }