from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional

# Import your existing logic (No changes needed there!)
from apps.detection.ml_logic.inference import analyze_traffic
from apps.reasoning.rag_logic.threat_analyzer import get_llm_reasoning
from apps.response.rl_logic.dqn_agent import get_mitigation_action

app = FastAPI(title="ACDAN API", description="Autonomous Cyber Defense Agent Network")

# --- Schemas (Pydantic) ---
class TrafficData(BaseModel):
    source_ip: str
    dest_ip: str
    features: Dict[str, float]

class ReasoningInput(BaseModel):
    threat_type: str
    confidence: float
    risk_level: str

# --- Routes ---

@app.get("/")
def read_root():
    return {"status": "ACDAN System Online", "version": "0.1.0-fastapi"}

@app.post("/api/detection/analyze")
async def detection_route(data: TrafficData):
    try:
        # Call your existing PyTorch logic
        results = analyze_traffic(data.features) 
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/reasoning/reason")
async def reasoning_route(data: ReasoningInput):
    # Call your Ollama/Mistral logic
    analysis = get_llm_reasoning(data.threat_type, data.confidence, data.risk_level)
    return analysis

@app.post("/api/response/execute")
async def response_route(data: Dict):
    # Call your RL/DQN logic
    action = get_mitigation_action(data['threat_type'], data['risk_level'])
    return action

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)