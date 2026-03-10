import os
import sys
from pathlib import Path


# Project root
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

    print("Initializing ACDAN RAG System...")

    # Paths
    cve_dir = PROJECT_ROOT / "data" / "cve_db"
    cve_json = cve_dir / "cve_database.json"
    faiss_path = cve_dir / "cve_index.faiss"

    # Ensure directory exists
    if not cve_dir.exists():
        print(f"Creating directory: {cve_dir}")
        cve_dir.mkdir(parents=True, exist_ok=True)

    # Initialize loader
    loader = CVELoader(cve_database_path=str(cve_json))

    # Load CVE data
    print("Loading CVE database...")
    loader.load_cve_database()

    # Build FAISS index
    print("Building FAISS vector index...")
    index = loader.build_index(model_name="all-MiniLM-L6-v2")

    # Save index
    print(f"Saving FAISS index to {faiss_path}")
    index.save(str(faiss_path))

    print("\nInitialization completed successfully.")
    print(f"Database file : {cve_json}")
    print(f"FAISS index   : {faiss_path}")


if __name__ == "__main__":
    main()