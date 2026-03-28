from fastapi import APIRouter, HTTPException
from .schemas import IngestLogRequest, PredictionResponse
from .services import detection_service
from apps.reasoning.services import reasoning_service 
from apps.response.services import response_service   

router = APIRouter(prefix="/detection", tags=["Detection"])

@router.post("/analyze")
async def analyze_and_act(data: IngestLogRequest):
    try:
        # 1. DETECTION PHASE (ML)
        prediction = detection_service.predict(data.features)
        
        if prediction["threat_level"] == "LOW":
            return {"status": "clear", "analysis": "Traffic is benign."}

        # 2. REASONING PHASE (RAG + LLM)
        # We pass the ML results to the LLM for deep analysis
        reasoning_data = {
            "predicted_class": prediction["predicted_class"],
            "confidence": prediction["confidence"],
            "source_ip": data.source_ip,
            "dest_ip": data.dest_ip,
            "protocol": data.protocol,
            "port": data.port,
            "threat_level": prediction["threat_level"]
        }
        ai_analysis = await reasoning_service.generate_analysis(reasoning_data)

        # 3. RESPONSE PHASE (RL)
        # We pass the risk level to the RL agent to get the best action
        mitigation = response_service.determine_action(
            predicted_class=prediction["predicted_class"],
            risk_level=ai_analysis["risk_level"]
        )

        # 4. UNIFIED RESPONSE
        return {
            "detection": prediction,
            "reasoning": ai_analysis,
            "mitigation": mitigation
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))