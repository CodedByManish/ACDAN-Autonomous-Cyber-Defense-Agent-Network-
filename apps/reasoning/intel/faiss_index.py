"""
FAISS-based vector index for threat intelligence retrieval.
"""

import faiss
import numpy as np
from typing import List, Tuple, Dict
import pickle
import os


class FAISSIndex:
    """FAISS vector index for RAG."""
    
    def __init__(self, embedding_dim: int = 384):
        """
        Initialize FAISS index.
        
        Args:
            embedding_dim: Dimension of embeddings
        """
        self.embedding_dim = embedding_dim
        self.index = faiss.IndexFlatL2(embedding_dim)
        self.documents = []
        self.metadata = []
    
    def add_documents(
        self,
        embeddings: np.ndarray,
        documents: List[str],
        metadata: List[Dict] = None
    ) -> None:
        """
        Add documents to index.
        
        Args:
            embeddings: Document embeddings
            documents: Document texts
            metadata: Optional metadata
        """
        if embeddings.dtype != np.float32:
            embeddings = embeddings.astype(np.float32)
        
        self.index.add(embeddings)
        self.documents.extend(documents)
        
        if metadata:
            self.metadata.extend(metadata)
        else:
            self.metadata.extend([{} for _ in documents])
        
        print(f"Added {len(documents)} documents. Index size: {self.index.ntotal}")
    
    def search(self, query_embedding: np.ndarray, k: int = 5) -> List[Tuple]:
        """
        Search for similar documents.
        
        Args:
            query_embedding: Query embedding
            k: Number of results to return
            
        Returns:
            List of (distance, index, document, metadata) tuples
        """
        if query_embedding.dtype != np.float32:
            query_embedding = query_embedding.astype(np.float32)
        
        query_embedding = query_embedding.reshape(1, -1)
        distances, indices = self.index.search(query_embedding, k)
        
        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx >= 0 and idx < len(self.documents):
                results.append((
                    float(dist),
                    int(idx),
                    self.documents[idx],
                    self.metadata[idx]
                ))
        
        return results
    
    def save(self, filepath: str) -> None:
        """Save index to disk."""
        data = {
            'index': self.index,
            'documents': self.documents,
            'metadata': self.metadata,
            'embedding_dim': self.embedding_dim,
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(data, f)
        
        print(f"Index saved to {filepath}")
    
    def load(self, filepath: str) -> None:
        """Load index from disk."""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        
        self.index = data['index']
        self.documents = data['documents']
        self.metadata = data['metadata']
        self.embedding_dim = data['embedding_dim']
        
        print(f"Index loaded from {filepath}. Size: {self.index.ntotal}")