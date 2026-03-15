import os
import sys
import faiss
from pathlib import Path

# Project root setup
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

# Import RAG components
try:
    from apps.rag_intelligence.logic.cve_loader import CVELoader
except ImportError:
    print("Error: CVELoader module not found. Verify project structure.")
    sys.exit(1)

def main() -> None:
    """Initialize CVE database and build FAISS vector index."""
    print("--- ACDAN RAG Initialization ---")

    # Paths
    cve_dir = PROJECT_ROOT / "data" / "cve_db"
    cve_json = cve_dir / "cve_database.json"
    faiss_path = cve_dir / "cve_index.faiss"

    if not cve_dir.exists():
        print(f"Creating directory: {cve_dir}")
        cve_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load Data
    loader = CVELoader(cve_database_path=str(cve_json))
    print("Loading CVE database...")
    loader.load_cve_database()

    # 2. Build Index
    print("Building FAISS vector index (all-MiniLM-L6-v2)...")
    result = loader.build_index(model_name="all-MiniLM-L6-v2")

    # 3. Save Index (The Fix)
    print(f"Saving FAISS index to {faiss_path}")
    
    actual_index = getattr(result, 'index', result)
    
    try:
        faiss.write_index(actual_index, str(faiss_path))
        print("\nInitialization completed successfully.")
    except Exception as e:
        print(f"\nFailed to save index: {e}")
        print("Tip: Ensure 'actual_index' is a faiss.Index object.")

if __name__ == "__main__":
    main()