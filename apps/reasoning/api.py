from fastapi import APIRouter, HTTPException, BackgroundTasks
from .schemas import ReasoningRequest, ReasoningResponse
from .services import reasoning_service
import logging

# Standard FastAPI logging setup
logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/reasoning",
    tags=["Reasoning & RAG Intelligence"]
)

@router.post("/reason", response_model=ReasoningResponse)
async def reason_threat(data: ReasoningRequest):
    """
    Performs high-fidelity threat reasoning using Mistral + RAG.
    This replaces the old Django-Ninja endpoint.
    """
    try:
        # Convert Pydantic model to dict for the service layer
        payload = data.dict()
        
        # Calling the async service we just refined
        analysis = await reasoning_service.generate_analysis(payload)
        
        # Ensure the response matches your ReasoningResponse schema
        return ReasoningResponse(
            threat_summary=analysis.get("threat_summary", "Analysis unavailable"),
            recommendations=analysis.get("recommendations", ["Monitor network"]),
            risk_level=analysis.get("risk_level", data.threat_level),
            cve_context_used=analysis.get("cve_context_used", "None")
        )

    except Exception as e:
        logger.error(f"Critical Reasoning Error: {str(e)}")
        # Provide a safe fallback so the pipeline doesn't crash
        return ReasoningResponse(
            threat_summary=f"AI Reasoning Engine encountered an error: {str(e)}",
            recommendations=["Manual investigation required", "Isolate source IP"],
            risk_level="CRITICAL",
            cve_context_used="Context retrieval failed"
        )

@router.get("/status")
async def get_reasoning_status():
    """Check if the RAG Index and LLM are ready."""
    is_ready = reasoning_service.index is not None
    return {
        "agent": "Reasoning_Agent_v1",
        "rag_index_loaded": is_ready,
        "llm_model": reasoning_service.model_name
    }