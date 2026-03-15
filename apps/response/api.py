from ninja import Router, Schema
from services import response_service

router = Router()

class ResponseRequest(Schema):
    predicted_class: str
    risk_level: str

@router.post("/execute")
def execute_response(request, data: ResponseRequest):
    result = response_service.determine_action(data.predicted_class, data.risk_level)
    return result