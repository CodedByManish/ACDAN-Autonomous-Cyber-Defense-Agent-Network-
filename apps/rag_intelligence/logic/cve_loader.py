"""
Load CVE database and build RAG index.
"""

import json
import csv
from typing import List, Dict
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from .embeddings import EmbeddingGenerator
from .faiss_index import FAISSIndex


class CVELoader:
    """Load CVE database and create searchable index."""
    
    def __init__(self, cve_database_path: str = "./data/cve_database.json"):
        """
        Initialize CVE loader.
        
        Args:
            cve_database_path: Path to CVE database file
        """
        self.cve_database_path = Path(cve_database_path)
        self.cves = []
        self.index = None
        self.embeddings_generator = None
    
    def load_cve_database(self) -> List[Dict]:
        """
        Load CVE database from file.
        
        Returns:
            List of CVE records
        """
        if not self.cve_database_path.exists():
            print(f"Creating sample CVE database at {self.cve_database_path}")
            self._create_sample_database()
        
        with open(self.cve_database_path, 'r') as f:
            self.cves = json.load(f)
        
        print(f"Loaded {len(self.cves)} CVEs")
        return self.cves
    
    def build_index(self, model_name: str = "all-MiniLM-L6-v2") -> FAISSIndex:
        """
        Build searchable index from CVEs.
        
        Args:
            model_name: Embedding model name
            
        Returns:
            FAISS index
        """
        if not self.cves:
            self.load_cve_database()
        
        # Initialize embedding generator
        self.embeddings_generator = EmbeddingGenerator(model_name)
        
        # Prepare texts for embedding
        texts = [
            f"{cve['id']}: {cve.get('description', '')} {cve.get('attack_vector', '')}"
            for cve in self.cves
        ]
        
        # Generate embeddings
        print("Generating embeddings...")
        embeddings = self.embeddings_generator.encode(texts)
        
        # Create FAISS index
        self.index = FAISSIndex(embedding_dim=embeddings.shape[1])
        self.index.add_documents(embeddings, texts, self.cves)
        
        return self.index
    
    def search_cves(
        self,
        query: str,
        k: int = 5
    ) -> List[Dict]:
        """
        Search for relevant CVEs.
        
        Args:
            query: Search query
            k: Number of results
            
        Returns:
            List of relevant CVEs
        """
        if self.index is None or self.embeddings_generator is None:
            self.build_index()
        
        # Encode query
        query_embedding = self.embeddings_generator.encode_single(query)
        
        # Search
        results = self.index.search(query_embedding, k)
        
        return [
            {
                'distance': dist,
                'cve': metadata,
                'similarity_score': 1 / (1 + dist)  # Convert distance to similarity
            }
            for dist, _, _, metadata in results
        ]
    
    def _create_sample_database(self) -> None:
        """Create sample CVE database for testing."""
        sample_cves = [
            {
                "id": "CVE-2023-12345",
                "description": "Buffer overflow in Apache HTTP Server",
                "attack_vector": "NETWORK",
                "impact": "CRITICAL",
                "affected_versions": ["2.4.0-2.4.54"],
                "remediation": "Upgrade to Apache 2.4.55 or later"
            },
            {
                "id": "CVE-2023-54321",
                "description": "SQL Injection vulnerability in WordPress",
                "attack_vector": "NETWORK",
                "impact": "HIGH",
                "affected_versions": ["6.0-6.2"],
                "remediation": "Update WordPress to version 6.2.3"
            },
            {
                "id": "CVE-2023-99999",
                "description": "Privilege escalation in Linux kernel",
                "attack_vector": "LOCAL",
                "impact": "CRITICAL",
                "affected_versions": ["5.10-6.1"],
                "remediation": "Apply kernel security patch"
            },
            {
                "id": "CVE-2023-11111",
                "description": "Remote Code Execution in Nginx",
                "attack_vector": "NETWORK",
                "impact": "CRITICAL",
                "affected_versions": ["1.20-1.24"],
                "remediation": "Upgrade Nginx to 1.24.1"
            },
            {
                "id": "CVE-2023-22222",
                "description": "Authentication bypass in SSH",
                "attack_vector": "NETWORK",
                "impact": "CRITICAL",
                "affected_versions": ["7.0-8.0"],
                "remediation": "Update SSH server and disable key exchange methods"
            },
        ]
        
        self.cve_database_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.cve_database_path, 'w') as f:
            json.dump(sample_cves, f, indent=2)
        
        print(f"Created sample CVE database with {len(sample_cves)} entries")