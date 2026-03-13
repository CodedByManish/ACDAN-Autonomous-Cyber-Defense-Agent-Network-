# apps/detection/api.py
from ninja import Router
from .schemas import IngestLogRequest, PredictionResponse
from .services import detection_service
from .models import ThreatAlert

router = Router()

@router.post("/analyze", response_model=PredictionResponse)
def analyze_packet(request, data: IngestLogRequest):
    # 1. Get prediction from ML Engine
    prediction = detection_service.predict(data.features)
    
    # 2. Log high-threat alerts to the Django Database
    if prediction['threat_level'] in ['HIGH', 'CRITICAL']:
        ThreatAlert.objects.create(
            attack_type=prediction['predicted_class'],
            source_ip=data.source_ip,
            dest_ip=data.dest_ip,
            risk_level=prediction['threat_level'],
            confidence=prediction['confidence'],
            threat_summary=f"Detected {prediction['predicted_class']} from {data.source_ip}"
        )
        
    return prediction