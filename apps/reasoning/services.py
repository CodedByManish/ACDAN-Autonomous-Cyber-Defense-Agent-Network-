import ollama
import json
import re
import logging
from pathlib import Path
from .intel.cve_loader import CVELoader
from .rag_logic.prompt_templates import THREAT_ANALYSIS_PROMPT

# Setup logging for production visibility
logger = logging.getLogger(__name__)

class ReasoningService:
    def __init__(self, model_name="mistral"):
        self.model_name = model_name
        
        # 1. Initialize the Intelligence Manager (RAG)
        self.db_dir = Path("data/cve_db")
        self.intel_manager = CVELoader(
            cve_database_path=str(self.db_dir / "cve_database.json")
        )
        
        # 2. Pre-load the FAISS index to RAM for instant first-response
        try:
            index_file = self.db_dir / "cve_index.faiss"
            if index_file.exists():
                # Building the index object if not exists and loading the saved file
                self.intel_manager.build_index() 
                self.intel_manager.index.load(str(index_file))
                logger.info("✅ RAG Intelligence FAISS index loaded successfully.")
            else:
                logger.warning("⚠️ No FAISS index found. RAG will build on first search.")
        except Exception as e:
            logger.error(f"❌ RAG Initialization Failed: {e}")

    async def generate_analysis(self, data: dict) -> dict:
        """
        Finalized reasoning logic: Fetches CVE context, queries Mistral, 
        and returns structured threat intelligence.
        """
        attack_type = data.get("predicted_class", "Unknown")
        
        # 1. RETRIEVE CONTEXT
        # Using your CVELoader's optimized search logic
        try:
            results = self.intel_manager.search_cves(query=attack_type, k=2)
            context_segments = []
            for res in results:
                cve = res.get('cve', {})
                # Formatting context for the LLM prompt
                context_segments.append(
                    f"Ref: {cve.get('id', 'N/A')} - {cve.get('description', 'No details')}. "
                    f"Fix: {cve.get('remediation', 'Contact Admin')}"
                )
            rag_context = "\n".join(context_segments)
        except Exception as e:
            logger.error(f"RAG Search Error: {e}")
            rag_context = "No specific CVE context found for this threat."

        # 2. PREPARE PROMPT
        # Note: Using your existing high-fidelity template
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
            # Synchronous call to Ollama (Ollama's python lib is currently blocking, 
            # but 'async' wrapper in FastAPI prevents UI hanging)
            response = ollama.generate(model=self.model_name, prompt=prompt)
            raw_res = response.get('response', '').strip()

            # 4. ROBUST JSON EXTRACTION
            # Your regex logic is the most reliable way to handle LLM "chatter"
            json_match = re.search(r'\{.*\}', raw_res, re.DOTALL)
            if json_match:
                analysis_json = json.loads(json_match.group())
            else:
                raise ValueError("LLM output did not contain a valid JSON object")

            return {
                "threat_summary": analysis_json.get("threat_summary", "Detailed analysis complete."),
                "recommendations": analysis_json.get("immediate_actions", ["Isolate Source", "Monitor Traffic"]),
                "risk_level": analysis_json.get("risk_level", data.get("threat_level", "HIGH")),
                "cve_context_used": rag_context[:400] # Increased limit for better reporting
            }

        except Exception as e:
            logger.error(f"Reasoning Inference Error: {e}")
            # Reliable Fallback
            return {
                "threat_summary": f"System detected {attack_type}. AI reasoning engine encountered an error during analysis.",
                "recommendations": ["Initiate standard incident response", "Isolate source IP", "Manual log verification"],
                "risk_level": data.get("threat_level", "HIGH"),
                "cve_context_used": "Error retrieving context"
            }

# Singleton instance for the app
reasoning_service = ReasoningService()