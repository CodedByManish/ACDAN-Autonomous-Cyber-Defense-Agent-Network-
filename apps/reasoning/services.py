import ollama
import json
import faiss
import os
import numpy as np
from pathlib import Path
from sentence_transformers import SentenceTransformer

class ReasoningService:
    def __init__(self, model_name="mistral"):
        self.model_name = model_name
        # Use a consistent path relative to the project root
        self.db_path = Path("data/cve_db")
        self.embed_model = SentenceTransformer('all-MiniLM-L6-v2')
        self._index = None
        self._cve_data = None

    @property
    def index(self):
        """Lazy load the FAISS index and JSON metadata."""
        if self._index is None:
            index_path = str(self.db_path / "cve_index.faiss")
            json_path = self.db_path / "cve_database.json"
            
            if not os.path.exists(index_path) or not os.path.exists(json_path):
                print(f"CRITICAL: RAG Files missing in {self.db_path}")
                return None
            
            print(f"--- Loading RAG Database ---")
            self._index = faiss.read_index(index_path)
            with open(json_path, "r") as f:
                self._cve_data = json.load(f)
        return self._index

    def _get_rag_context(self, query: str, top_k: int = 2):
        if self.index is None:
            return "No local CVE context available."

        query_vector = self.embed_model.encode([query]).astype('float32')
        distances, indices = self.index.search(query_vector, top_k)
        
        context_list = []
        for idx in indices[0]:
            if idx != -1 and idx < len(self._cve_data):
                item = self._cve_data[idx]
                cid = item.get('cve_id', 'N/A')
                desc = item.get('description', 'No details available')
                context_list.append(f"- {cid}: {desc}")
        
        return "\n".join(context_list) if context_list else "No relevant CVE context found."

    def generate_analysis(self, detection_data: dict):
        """
        Takes detection results and generates an AI-powered explanation.
        """
        attack_type = detection_data.get("predicted_class", "Unknown")
        rag_context = self._get_rag_context(attack_type)
        
        prompt = f"""
        [SYSTEM: SENIOR CYBERSECURITY ANALYST]
        Analyze this {attack_type} threat. 
        CVE Context: {rag_context}
        
        Return ONLY a JSON object:
        {{
            "threat_summary": "Detailed explanation...",
            "recommendations": ["Step 1", "Step 2", "Step 3"]
        }}
        """
        
        try:
            # Talk to Ollama
            response = ollama.generate(model=self.model_name, prompt=prompt)
            raw_res = response.get('response', '').strip()
            
            print(f"--- MISTRAL RESPONSE RECEIVED ---")

            # Robust JSON Extraction
            start = raw_res.find('{')
            end = raw_res.rfind('}') + 1
            if start != -1 and end > start:
                analysis_json = json.loads(raw_res[start:end])
            else:
                raise ValueError("Response did not contain valid JSON")

        except Exception as e:
            print(f"Reasoning logic error: {e}")
            analysis_json = {
                "threat_summary": f"System detected {attack_type}. AI analysis unavailable.",
                "recommendations": ["Isolate source IP", "Monitor logs", "Update firewall"]
            }

        # Final dictionary returned to the API
        return {
            "threat_summary": analysis_json.get("threat_summary", "No summary provided"),
            "recommendations": analysis_json.get("recommendations", []),
            "risk_level": detection_data.get("threat_level") or "HIGH",
            "cve_context_used": rag_context[:200]
        }

reasoning_service = ReasoningService()