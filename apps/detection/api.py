from fastapi import APIRouter, HTTPException
from .schemas import IngestLogRequest
from .services import detection_service
from apps.reasoning.services import reasoning_service 
from apps.response.services import response_service   

router = APIRouter(prefix="/detection", tags=["Detection"])
@router.post("/analyze")
async def analyze_and_act(data: IngestLogRequest):
    try:
        # 1. DETECTION PHASE
        prediction = detection_service.predict(data.features)
        
        # Determine if it's a threat based on your mapping
        is_threat = prediction["threat_level"] != "LOW"

        # Base response structure
        response = {
            "is_threat": is_threat,
            "threat_type": prediction["predicted_class"],
            "confidence_score": prediction["confidence"],
            "threat_level": prediction["threat_level"]
        }

        if not is_threat:
            return {**response, "status": "clear", "analysis": "Traffic is benign."}

        # 2. REASONING PHASE
        reasoning_data = {
            "predicted_class": prediction["predicted_class"],
            "confidence": prediction["confidence"],
            "source_ip": data.source_ip,
            "threat_level": prediction["threat_level"]
        }
        ai_analysis = await reasoning_service.generate_analysis(reasoning_data)

        # 3. RESPONSE PHASE
        mitigation = response_service.determine_action(
            predicted_class=prediction["predicted_class"],
            risk_level=ai_analysis.get("risk_level", "MEDIUM")
        )

        return {
            **response,
            "reasoning": ai_analysis,
            "mitigation": mitigation
        }

    except Exception as e:
        import traceback
        print(traceback.format_exc()) # Crucial for debugging Terminal 1
        raise HTTPException(status_code=500, detail=str(e))