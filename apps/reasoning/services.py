import ollama
import json
import re
import logging
from pathlib import Path
from .intel.cve_loader import CVELoader
from .rag_logic.prompt_templates import THREAT_ANALYSIS_PROMPT
# Import the logging utility
from apps.response.utils import log_incident 

logger = logging.getLogger(__name__)

class ReasoningService:
    def __init__(self, model_name="phi3"):
        self.model_name = model_name
        self.db_dir = Path("data/cve_db")
        self.index_path = str(self.db_dir / "cve_index.faiss")
        
        # 1. Initialize Intelligence Manager
        self.intel_manager = CVELoader(
            cve_database_path=str(self.db_dir / "cve_database.json")
        )
        
        # 2. Lazy Load/Build Strategy
        self._bootstrap_rag()

    def _bootstrap_rag(self):
        """Ensures index is ready without redundant embedding generation."""
        try:
            if Path(self.index_path).exists() and Path(self.index_path + ".meta").exists():
                self.intel_manager.build_index() 
                self.intel_manager.index.load(self.index_path)
                logger.info("✅ RAG Intelligence loaded from FAISS disk cache.")
            else:
                logger.warning("⚠️ Cache miss: RAG will generate embeddings on first search.")
        except Exception as e:
            logger.error(f"❌ Initialization Error: {e}")

    async def generate_analysis(self, data: dict) -> dict:
        attack_type = data.get("predicted_class", "Unknown")
        
        # 1. SEARCH WITH AUTO-SAVE
        try:
            results = self.intel_manager.search_cves(query=attack_type, k=2)
            
            if not Path(self.index_path).exists() and self.intel_manager.index.index.ntotal > 0:
                self.intel_manager.index.save(self.index_path)
                logger.info("💾 FAISS Index persisted to disk.")

            rag_context = ""
            for res in results:
                cve = res[3] if isinstance(res, tuple) else {}
                rag_context += f"ID: {cve.get('id')} | Desc: {cve.get('description')}\n"
        except Exception as e:
            logger.error(f"Search Error: {e}")
            rag_context = "No context available."

        # 2. LLM REASONING
        prompt = THREAT_ANALYSIS_PROMPT.format(
            attack_type=attack_type,
            confidence=data.get("confidence", 0.0),
            source_ip=data.get("source_ip", "0.0.0.0"),
            dest_ip=data.get("dest_ip", "127.0.0.1"),
            protocol=data.get("protocol", "TCP"),
            port=data.get("port", 80),
            cve_context=rag_context
        )

        try:
            response = ollama.generate(model=self.model_name, prompt=prompt)
            raw_text = response.get('response', '')
            
            match = re.search(r'\{.*\}', raw_text, re.DOTALL)
            analysis = json.loads(match.group()) if match else {"risk_level": "MEDIUM"}
            
            # --- INTEGRATION: LOG THE INCIDENT ---
            # We log the detection and reasoning results before returning
            log_incident(
                threat_type=attack_type,
                risk_level=analysis.get("risk_level", "MEDIUM"),
                action="REASONING_COMPLETED" # We'll refine this as we connect the RL phase
            )
            
            return {
                "threat_summary": analysis.get("threat_summary", "Manual review required."),
                "risk_level": analysis.get("risk_level", "MEDIUM"),
                "cve_context_used": rag_context[:300]
            }
        except Exception as e:
            logger.error(f"Reasoning Error: {e}")
            return {"threat_summary": f"Error: {str(e)}", "risk_level": "HIGH"}

reasoning_service = ReasoningService()