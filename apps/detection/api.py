from fastapi import APIRouter, HTTPException
from .schemas import IngestLogRequest, PredictionResponse
from .services import detection_service
# Note: Database logic will be handled via an Async ORM later

router = APIRouter(prefix="/detection", tags=["Detection"])

@router.post("/analyze", response_model=PredictionResponse)
async def analyze_packet(data: IngestLogRequest):
    try:
        # We use 'async' because FastAPI thrives on non-blocking calls
        prediction = detection_service.predict(data.features)
        
        # Determine threat status
        is_threat = prediction["threat_level"] != "LOW"
        
        # Logic for 'Recommended Action' (Keeping your existing logic)
        action = "Isolate IP" if prediction["threat_level"] == "CRITICAL" else "Monitor"
        
        return {
            "is_threat": is_threat,
            "threat_type": prediction["predicted_class"],
            "confidence_score": prediction["confidence"],
            "recommended_action": action,
            "metadata": prediction["all_probabilities"],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))