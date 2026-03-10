import os
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .rag_logic.threat_analyzer import LLMThreatAnalyzer
from rag_intelligence.logic.cve_loader import CVELoader

# --- Initialization ---
CVE_JSON = "./data/cve_db/cve_database.json"
FAISS_INDEX = "./data/cve_db/cve_index.faiss"

# Global objects to keep index in memory
cve_loader = CVELoader(cve_database_path=CVE_JSON)
analyzer = LLMThreatAnalyzer(llm_type="ollama", model_name="mistral")

# Load pre-built FAISS index if available
try:
    if os.path.exists(FAISS_INDEX):
        from rag_intelligence.logic.faiss_index import FAISSIndex
        from rag_intelligence.logic.embeddings import EmbeddingGenerator

        cve_loader.index = FAISSIndex()
        cve_loader.index.load(FAISS_INDEX)
        cve_loader.embeddings_generator = EmbeddingGenerator()
        print("RAG Index loaded successfully.")
    else:
        print("Warning: FAISS index not found. Run scripts/initialize_rag.py first.")
except Exception as e:
    print(f"Error loading RAG index: {e}")


@csrf_exempt
def analyze_threat_details(request):
    """
    Analyze threat data with RAG context and LLM reasoning.
    Expects POST with JSON containing attack info.
    """
    if request.method != 'POST':
        return JsonResponse({"message": "Send threat data via POST"}, status=405)

    try:
        data = json.loads(request.body)
        attack_type = data.get('predicted_class', 'unknown')

        # Retrieve CVE context
        cve_context = ""
        if cve_loader.index:
            results = cve_loader.search_cves(query=attack_type, k=2)
            for res in results:
                c = res['cve']
                cve_context += f"Reference: {c['id']} - {c['description']}. Fix: {c['remediation']}\n"

        # LLM reasoning
        analysis = analyzer.analyze_threat(
            attack_type=attack_type,
            confidence=data.get('confidence', 0.0),
            source_ip=data.get('source_ip', '0.0.0.0'),
            dest_ip=data.get('dest_ip', '127.0.0.1'),
            protocol=data.get('protocol', 'TCP'),
            port=data.get('port', 80),
            cve_context=cve_context
        )

        return JsonResponse(analysis)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)