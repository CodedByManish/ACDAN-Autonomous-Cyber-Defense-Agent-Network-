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
        # Load embedding model once
        self.embed_model = SentenceTransformer('all-MiniLM-L6-v2')
        self.db_path = Path("./data/cve_db")
        
        # Internal placeholders for lazy loading
        self._index = None
        self._cve_data = None

    @property
    def index(self):
        """Lazy load the FAISS index only when needed."""
        if self._index is None:
            index_path = str(self.db_path / "cve_index.faiss")
            if not os.path.exists(index_path):
                print(f"CRITICAL: {index_path} not found!")
                return None
            
            print(f"--- Loading FAISS Index from {index_path} ---")
            self._index = faiss.read_index(index_path)
            
            # Also load the JSON metadata at the same time
            json_path = self.db_path / "cve_database.json"
            with open(json_path, "r") as f:
                self._cve_data = json.load(f)
                
        return self._index

    def _get_rag_context(self, query: str, top_k: int = 2):
        """Retrieve relevant CVE info using the lazy-loaded index."""
        # Safety check: if index fails to load
        if self.index is None:
            return "No local CVE context available."

        query_vector = self.embed_model.encode([query]).astype('float32')
        # We call self.index which triggers the @property method above
        distances, indices = self.index.search(query_vector, top_k)
        
        context_list = []
        for idx in indices[0]:
            # indices[0] contains the matched IDs from FAISS
            if idx != -1 and idx < len(self._cve_data):
                item = self._cve_data[idx]
                cid = item.get('cve_id') or item.get('id') or "N/A"
                desc = item.get('description') or item.get('summary') or "No details"
                context_list.append(f"- {cid}: {desc}")
        
        final_context = "\n".join(context_list)
        print(f"--- RAG MATCHES FOUND: {len(context_list)} ---")
        return final_context if final_context else "No relevant CVE context found."

    def generate_analysis(self, detection_data: dict):
        attack_type = detection_data.get("predicted_class", "Unknown")
        
        # 1. FIX THE NAME HERE (Removed the extra '_get_')
        rag_context = self._get_rag_context(attack_type) 
        
        prompt = f"""
        [SYSTEM: SENIOR CYBERSECURITY ANALYST]
        Analyze the following cyber threat: {attack_type}.
        Context: {rag_context}
        Return ONLY a JSON object with keys:
        "threat_summary": (string explanation)
        "recommendations": (list of 3 strings)
        """
        
        try:
            response = ollama.generate(model=self.model_name, prompt=prompt)
            raw_res = response.get('response', '')
            
            print(f"--- MISTRAL RAW OUTPUT ---\n{raw_res}\n--------------------------")

            start = raw_res.find('{')
            end = raw_res.rfind('}') + 1
            
            if start != -1 and end > start:
                analysis_json = json.loads(raw_res[start:end])
            else:
                raise ValueError("No valid JSON found")

        except Exception as e:
            print(f"Reasoning logic failed: {e}")
            analysis_json = {
                "threat_summary": f"Detection confirmed {attack_type}. Automated reasoning encountered an error.",
                "recommendations": ["Verify network traffic", "Update firewall rules"]
            }

        # Ensure the keys here match exactly what the Test Script is looking for
        return {
            "threat_summary": analysis_json.get("threat_summary", "No summary provided"),
            "recommendations": analysis_json.get("recommendations", []),
            "risk_level": detection_data.get("threat_level", "HIGH"),
            "cve_context_used": rag_context[:200] if rag_context else "None"
        }

# Instantiate once
reasoning_service = ReasoningService()