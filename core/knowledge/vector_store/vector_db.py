import os
import json
import threading
import numpy as np # type: ignore
from typing import Any, Dict, List, Optional, Tuple

class VectorDB:
    """
    Extracted from modules/embeddings.py.
    Manages persistence and retrieval of vector embeddings and metadata.
    """

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self.vector_cache_path = os.path.join(self.data_dir, "vector_index.npz")
        self.meta_cache_path = os.path.join(self.data_dir, "vector_metadata.json")

        self._vectors: Optional[Any] = None
        self._metadata: List[Dict[str, Any]] = []
        self._data_lock = threading.Lock()
        
        self.load_index()

    def load_index(self) -> None:
        with self._data_lock:
            if os.path.exists(self.vector_cache_path) and os.path.exists(self.meta_cache_path):
                try:
                    loaded = np.load(self.vector_cache_path)
                    self._vectors = loaded["vectors"]
                    with open(self.meta_cache_path, "r", encoding="utf-8") as f:
                        self._metadata = json.load(f)
                    return
                except Exception as exc:
                    print(f"[VectorDB] Could not load index: {exc}")
            self._vectors = np.zeros((0, 384), dtype=np.float32)
            self._metadata = []

    def save_index(self) -> None:
        with self._data_lock:
            if self._vectors is not None:
                np.savez_compressed(self.vector_cache_path, vectors=self._vectors)
                with open(self.meta_cache_path, "w", encoding="utf-8") as f:
                    json.dump(self._metadata, f, indent=2, ensure_ascii=False)

    def update_index(self, vectors: np.ndarray, metadata: List[Dict[str, Any]]) -> None:
        with self._data_lock:
            self._vectors = vectors
            self._metadata = metadata
        self.save_index()

    def get_index_vectors_and_meta(self) -> Tuple[Optional[np.ndarray], List[Dict[str, Any]]]:
        with self._data_lock:
            return self._vectors, list(self._metadata)

    def get_index_size(self) -> int:
        with self._data_lock:
            return len(self._metadata)
