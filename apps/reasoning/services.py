import ollama
import json
import faiss
import os
import re
from pathlib import Path
from sentence_transformers import SentenceTransformer
from .rag_logic.prompt_templates import THREAT_ANALYSIS_PROMPT # Keeping your specific templates

class ReasoningService:
    def __init__(self, model_name="mistral"):
        self.model_name = model_name
        self.db_path = Path("data/cve_db")
        # High-accuracy embedding model
        self.embed_model = SentenceTransformer('all-MiniLM-L6-v2')
        self._index = None
        self._cve_data = None

    @property
    def index(self):
        """High-speed access to FAISS index."""
        if self._index is None:
            index_path = str(self.db_path / "cve_index.faiss")
            json_path = self.db_path / "cve_database.json"
            if os.path.exists(index_path) and os.path.exists(json_path):
                self._index = faiss.read_index(index_path)
                with open(json_path, "r") as f:
                    self._cve_data = json.load(f)
        return self._index

    def _get_rag_context(self, query: str, top_k: int = 2):
        if self.index is None:
            return "No local CVE context available."

        query_vector = self.embed_model.encode([query]).astype('float32')
        _, indices = self.index.search(query_vector, top_k)
        
        context_list = []
        for idx in indices[0]:
            if idx != -1 and idx < len(self._cve_data):
                item = self._cve_data[idx]
                cid = item.get('cve_id', 'N/A')
                desc = item.get('description', 'No details')
                context_list.append(f"- {cid}: {desc}")
        
        return "\n".join(context_list) if context_list else "No relevant context found."

    async def generate_analysis(self, data: dict):
        """
        Optimized for FastAPI. 
        Keeps your original logical flow for maximum accuracy.
        """
        attack_type = data.get("predicted_class", "Unknown")
        rag_context = self._get_rag_context(attack_type)
        
        # Use your high-detail template
        prompt = THREAT_ANALYSIS_PROMPT.format(
            attack_type=attack_type,
            confidence=data.get("confidence", 0.0),
            source_ip=data.get("source_ip", "0.0.0.0"),
            dest_ip=data.get("dest_ip", "127.0.0.1"),
            protocol=data.get("protocol", "TCP"),
            port=data.get("port", 80),
            cve_context=rag_context # Enhancing prompt with RAG
        )
        
        try:
            # Async-friendly call to Ollama
            response = ollama.generate(model=self.model_name, prompt=prompt)
            raw_res = response.get('response', '').strip()

            # Robust JSON extraction (Your original logic)
            json_match = re.search(r'\{.*\}', raw_res, re.DOTALL)
            if json_match:
                analysis_json = json.loads(json_match.group())
            else:
                raise ValueError("Valid JSON not found in LLM response")

            return {
                "threat_summary": analysis_json.get("threat_summary", "Summary generation failed."),
                "recommendations": analysis_json.get("immediate_actions", ["Monitor Traffic"]),
                "risk_level": analysis_json.get("risk_level", data.get("threat_level", "HIGH")),
                "cve_context_used": rag_context[:300]
            }

        except Exception as e:
            # Fallback that still preserves your data
            return {
                "threat_summary": f"Automated analysis for {attack_type} initiated. LLM Error: {str(e)}",
                "recommendations": ["Isolate IP", "Verify Logs"],
                "risk_level": data.get("threat_level", "HIGH"),
                "cve_context_used": rag_context[:200]
            }

reasoning_service = ReasoningService()