from fastapi import APIRouter, HTTPException
from .schemas import ResponseRequest, ResponseResponse
from .services import response_service

router = APIRouter(prefix="/response", tags=["Response & Mitigation"])

@router.post("/execute", response_model=ResponseResponse)
async def execute_response(data: ResponseRequest):
    """
    Executes the optimal mitigation strategy using a Deep Q-Network.
    """
    try:
        result = response_service.determine_action(
            predicted_class=data.predicted_class,
            risk_level=data.risk_level
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"RL Mitigation Engine Error: {str(e)}"
        )