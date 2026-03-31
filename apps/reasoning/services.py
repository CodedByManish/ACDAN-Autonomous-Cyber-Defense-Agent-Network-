import ollama
import json
import re
import logging
from pathlib import Path
from .intel.cve_loader import CVELoader
# Import the prompt if it's in a separate file
# from .rag_logic.prompt_templates import THREAT_ANALYSIS_PROMPT 

logger = logging.getLogger(__name__)

class ReasoningService:
    def __init__(self, model_name="mistral"):
        self.model_name = model_name
        self.db_dir = Path("data/cve_db")
        self.cve_json = self.db_dir / "cve_database.json"
        self.index_file = self.db_dir / "cve_index.faiss"
        
        # 1. Initialize the Intelligence Manager
        self.intel_manager = CVELoader(cve_database_path=str(self.cve_json))
        
        # 2. Smart Load Logic
        self._initialize_rag()

    def _initialize_rag(self):
        try:
            if self.index_file.exists():
                # Load existing index
                self.intel_manager.build_index() 
                self.intel_manager.index.load(str(self.index_file))
                logger.info("✅ FAISS index loaded from disk.")
            elif self.cve_json.exists():
                # Auto-build if JSON exists but index doesn't
                logger.info("⚙️ Index missing. Building FAISS index from JSON (this may take a moment)...")
                self.intel_manager.build_index()
                # Assuming your CVELoader has a method to save after building
                # If not, the first search will trigger the build anyway.
                logger.info("✅ Initial index structure prepared.")
            else:
                logger.error(f"❌ Critical Error: {self.cve_json} not found!")
        except Exception as e:
            logger.error(f"❌ RAG Initialization Failed: {e}")

    async def generate_analysis(self, data: dict) -> dict:
        attack_type = data.get("predicted_class", "Unknown")
        
        # 1. RETRIEVE CONTEXT
        try:
            # This method usually triggers internal build if not built
            results = self.intel_manager.search_cves(query=attack_type, k=2)
            
            # If we just built the index for the first time, save it now!
            if not self.index_file.exists():
                self.intel_manager.index.save(str(self.index_file))
                logger.info(f"💾 Saved fresh FAISS index to {self.index_file}")

            context_segments = []
            for res in results:
                # Adjusting based on your search_cves return structure
                # res[3] is usually the metadata/cve dict in your FAISSIndex.search
                cve = res[3] if isinstance(res, tuple) else res.get('cve', {})
                context_segments.append(
                    f"Ref: {cve.get('id', 'N/A')} - {cve.get('description', 'No details')}. "
                    f"Fix: {cve.get('remediation', 'Contact Admin')}"
                )
            rag_context = "\n".join(context_segments)
        except Exception as e:
            logger.error(f"RAG Search Error: {e}")
            rag_context = "No specific CVE context found for this threat."

        # 2. PREPARE PROMPT (Using your high-fidelity template)
        # Note: I'm assuming THREAT_ANALYSIS_PROMPT is imported or defined
        from .rag_logic.prompt_templates import THREAT_ANALYSIS_PROMPT
        prompt = THREAT_ANALYSIS_PROMPT.format(
            attack_type=attack_type,
            confidence=data.get("confidence", 0.0),
            source_ip=data.get("source_ip", "0.0.0.0"),
            dest_ip=data.get("dest_ip", "127.0.0.1"),
            protocol=data.get("protocol", "TCP"),
            port=data.get("port", 80),
            cve_context=rag_context
        )

        # 3. LLM INFERENCE
        try:
            response = ollama.generate(model=self.model_name, prompt=prompt)
            raw_res = response.get('response', '').strip()

            # 4. ROBUST JSON EXTRACTION
            json_match = re.search(r'\{.*\}', raw_res, re.DOTALL)
            if json_match:
                analysis_json = json.loads(json_match.group())
                return {
                    "threat_summary": analysis_json.get("threat_summary", "Analysis complete."),
                    "recommendations": analysis_json.get("immediate_actions", ["Isolate Source"]),
                    "risk_level": analysis_json.get("risk_level", data.get("threat_level", "HIGH")),
                    "cve_context_used": rag_context[:500] 
                }
            else:
                raise ValueError("No JSON found in LLM response")

        except Exception as e:
            logger.error(f"LLM Error: {e}")
            return {
                "threat_summary": f"Detected {attack_type}. Reasoning engine error.",
                "recommendations": ["Standard Incident Response"],
                "risk_level": data.get("threat_level", "HIGH"),
                "cve_context_used": rag_context[:200]
            }

# Singleton instance
reasoning_service = ReasoningService()