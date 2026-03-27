"""
Generate embeddings for threat intelligence retrieval.
"""

from sentence_transformers import SentenceTransformer
from typing import List
import numpy as np


class EmbeddingGenerator:
    """Generate embeddings using SentenceTransformers."""
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize embedding generator.
        
        Args:
            model_name: HuggingFace model name
        """
        self.model = SentenceTransformer(model_name)
        self.embedding_dim = self.model.get_sentence_embedding_dimension()
        print(f"Loaded model: {model_name}, dim: {self.embedding_dim}")
    
    def encode(self, texts: List[str]) -> np.ndarray:
        """
        Encode texts to embeddings.
        
        Args:
            texts: List of text strings
            
        Returns:
            Array of embeddings
        """
        return self.model.encode(texts, convert_to_numpy=True)
    
    def encode_single(self, text: str) -> np.ndarray:
        """Encode single text."""
        return self.model.encode([text], convert_to_numpy=True)[0]