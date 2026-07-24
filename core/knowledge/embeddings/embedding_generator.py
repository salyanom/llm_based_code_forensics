import numpy as np # type: ignore
from typing import List, Optional

class EmbeddingGenerator:
    """
    Extracted from modules/embeddings.py.
    Generates semantic vectors using SentenceTransformers with a lightweight fallback.
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self._model = None
        self._init_model()

    def _init_model(self):
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
            self._model = SentenceTransformer(self.model_name)
        except Exception as exc:
            print(f"[EmbeddingGenerator] Notice: sentence-transformers lightweight mode ({exc}). Using TF-IDF/Hash embedding fallback.")
            self._model = None

    def encode(self, texts: List[str]) -> np.ndarray:
        """Encode a list of text strings into normalized vectors."""
        if not texts:
            return np.zeros((0, 384), dtype=np.float32)
            
        if self._model is not None:
            try:
                vectors = self._model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
                return np.array(vectors, dtype=np.float32)
            except Exception as e:
                pass

        # Lightweight hash/frequency vector embedding fallback if sentence-transformers is offline
        vectors = []
        for text in texts:
            vec = np.zeros(384, dtype=np.float32)
            words = text.lower().split()
            for w in words:
                idx = hash(w) % 384
                vec[idx] += 1.0
            norm = np.linalg.norm(vec)
            if norm > 0:
                vec /= norm
            vectors.append(vec)
        return np.array(vectors, dtype=np.float32)

    def encode_query(self, query: str) -> np.ndarray:
        return self.encode([query])[0]
