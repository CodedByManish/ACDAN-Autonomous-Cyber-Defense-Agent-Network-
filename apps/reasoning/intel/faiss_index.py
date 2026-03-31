import faiss
import numpy as np
from typing import List, Tuple, Dict
import pickle
import os

class FAISSIndex:
    """FAISS vector index for RAG with Native Persistence."""
    
    def __init__(self, embedding_dim: int = 384):
        self.embedding_dim = embedding_dim
        self.index = faiss.IndexFlatL2(embedding_dim)
        self.documents = []
        self.metadata = []
    
    def is_initialized(self, filepath: str) -> bool:
        """Check if both the index and metadata files exist."""
        return os.path.exists(filepath) and os.path.exists(filepath + ".meta")

    def add_documents(self, embeddings: np.ndarray, documents: List[str], metadata: List[Dict] = None) -> None:
        if embeddings.dtype != np.float32:
            embeddings = embeddings.astype(np.float32)
        
        self.index.add(embeddings)
        self.documents.extend(documents)
        self.metadata.extend(metadata if metadata else [{} for _ in documents])
        print(f"✅ Added {len(documents)} docs. Current Total: {self.index.ntotal}")
    
    def search(self, query_embedding: np.ndarray, k: int = 5) -> List[Tuple]:
        if self.index.ntotal == 0:
            return []
            
        if query_embedding.dtype != np.float32:
            query_embedding = query_embedding.astype(np.float32)
        
        query_embedding = query_embedding.reshape(1, -1)
        distances, indices = self.index.search(query_embedding, k)
        
        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if 0 <= idx < len(self.documents):
                results.append((float(dist), int(idx), self.documents[idx], self.metadata[idx]))
        return results
    
    def save(self, filepath: str) -> None:
        """Saves index natively and metadata via pickle."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        faiss.write_index(self.index, filepath)
        
        meta_path = filepath + ".meta"
        with open(meta_path, 'wb') as f:
            pickle.dump({
                'docs': self.documents, 
                'meta': self.metadata, 
                'dim': self.embedding_dim
            }, f)
        print(f"💾 Index & Meta saved to: {filepath}")
    
    def load(self, filepath: str) -> None:
        """Loads index natively and metadata via pickle."""
        if not self.is_initialized(filepath):
            raise FileNotFoundError(f"Index components missing at: {filepath}")

        self.index = faiss.read_index(filepath)
        
        meta_path = filepath + ".meta"
        with open(meta_path, 'rb') as f:
            data = pickle.load(f)
            self.documents = data['docs']
            self.metadata = data['meta']
            self.embedding_dim = data['dim']
        print(f"📖 Index loaded successfully. Size: {self.index.ntotal}")