import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Import your finalized routers
from apps.reasoning.api import router as reasoning_router
from apps.response.api import router as response_router
# from apps.detection.api import router as detection_router # Assuming detection is ready

app = FastAPI(
    title="ACDAN: AI-Powered Cyber Defense System",
    description="FastAPI-driven pipeline for Threat Detection, Reasoning, and Response.",
    version="2.0.0"
)

# 1. CORS Middleware (Essential for frontend integration like React)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Adjust this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"message": "Internal Pipeline Error", "detail": str(exc)}
    )

# 3. Include App Routers
app.include_router(reasoning_router)
app.include_router(response_router)
# app.include_router(detection_router)

@app.get("/")
async def root():
    return {
        "status": "online",
        "system": "ACDAN Core",
        "components": ["Detection", "Reasoning (RAG/Mistral)", "Response (RL/DQN)"]
    }

if __name__ == "__main__":
    # Run the server at 127.0.0.1:8000
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)