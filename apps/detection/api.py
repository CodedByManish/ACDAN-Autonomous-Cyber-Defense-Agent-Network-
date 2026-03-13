from ninja import Router
from .schemas import IngestLogRequest, PredictionResponse
from .services import detection_service
from .models import ThreatAlert

router = Router()

@router.post("/analyze")
def analyze_packet(request, data: IngestLogRequest):
    # Pass the WHOLE features dictionary from the request to the model
    prediction = detection_service.predict(data.features)

    if prediction["threat_level"] in ["HIGH", "CRITICAL"]:
        ThreatAlert.objects.create(
            attack_type=prediction["predicted_class"],
            source_ip=data.source_ip,
            dest_ip=data.dest_ip,
            risk_level=prediction["threat_level"],
            confidence=prediction["confidence"],
            threat_summary=f"Detected {prediction['predicted_class']} targeting {data.dest_ip}",
        )

    # Map the engine output to your PredictionResponse schema
    return {
        "is_threat": prediction["threat_level"] != "LOW",
        "threat_type": prediction["predicted_class"],
        "confidence_score": prediction["confidence"],
        "recommended_action": "Isolate IP" if prediction["threat_level"] == "CRITICAL" else "Monitor",
        "metadata": prediction["all_probabilities"],
    }