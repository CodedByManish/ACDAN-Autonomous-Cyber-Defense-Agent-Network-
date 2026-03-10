from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from .ml_logic.inference import AnomalyDetectionInference

# Initialize the detector once when the server starts
# Make sure your metadata.json and best_model.pt are in data/models/
try:
    detector = AnomalyDetectionInference(models_path="./data/models")
except Exception as e:
    detector = None
    print(f"Warning: Model not loaded yet. {e}")

@csrf_exempt
def detect_threat(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            if detector:
                result = detector.predict_single(data)
                return JsonResponse(result)
            else:
                return JsonResponse({"error": "Model not initialized"}, status=500)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    
    return JsonResponse({"message": "Send a POST request with packet data."}, status=405)