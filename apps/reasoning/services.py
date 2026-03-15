import ollama
import json
import faiss
import numpy as np
from pathlib import Path
from sentence_transformers import SentenceTransformer

class ReasoningService:
    def __init__(self, model_name="mistral"):
        self.model_name = model_name
        self.embed_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Load FAISS index and Metadata
        db_path = Path("./data/cve_db")
        self.index = faiss.read_index(str(db_path / "cve_index.faiss"))
        with open(db_path / "cve_database.json", "r") as f:
            self.cve_data = json.load(f)

    def _get_rag_context(self, query: str, top_k: int = 2):
        """Retrieve relevant CVE info from FAISS."""
        query_vector = self.embed_model.encode([query]).astype('float32')
        distances, indices = self.index.search(query_vector, top_k)
        
        context = ""
        for idx in indices[0]:
            if idx < len(self.cve_data):
                item = self.cve_data[idx]
                context += f"- {item['cve_id']}: {item['description']}\n"
        return context

    def generate_analysis(self, detection_data: dict):
        attack_type = detection_data.get("predicted_class", "Unknown")
        
        # Get real context from RAG
        rag_context = self._get_rag_context(attack_type)
        
        prompt = f"""
        [SYSTEM: SENIOR CYBERSECURITY ANALYST]
        DETECTION: {attack_type} ({detection_data.get('confidence', 0):.2%} confidence)
        CONTEXT FROM DATABASE:
        {rag_context}

        INSTRUCTIONS:
        Analyze this threat. Explain why it is dangerous and provide 3 technical mitigation steps.
        Answer ONLY in valid JSON format.
        """
        
        response = ollama.generate(model=self.model_name, prompt=prompt)
        
        # Try to extract JSON from Ollama response
        try:
            # Mistral sometimes adds prose; this helps extract just the JSON
            raw_res = response['response']
            start = raw_res.find('{')
            end = raw_res.rfind('}') + 1
            analysis_json = json.loads(raw_res[start:end])
        except:
            analysis_json = {"threat_summary": response['response']}

        return {
            **analysis_json,
            "risk_level": detection_data.get("threat_level", "HIGH"),
            "cve_context_used": rag_context[:200] + "..."
        }

reasoning_service = ReasoningService()