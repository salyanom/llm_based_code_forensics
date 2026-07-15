from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List, Optional, Tuple

import numpy as np  # type: ignore
from config_manager import ConfigManager


class EmbeddingsModule:
    """Dedicated Embeddings Pipeline for vectorizing security knowledge and incremental indexing."""

    _instance: Optional["EmbeddingsModule"] = None
    _lock = threading.Lock()

    def __init__(self):
        self.config = ConfigManager.get_instance()
        self.root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.data_dir = os.path.join(self.root_dir, "data")
        os.makedirs(self.data_dir, exist_ok=True)
        self.vector_cache_path = os.path.join(self.data_dir, "vector_index.npz")
        self.meta_cache_path = os.path.join(self.data_dir, "vector_metadata.json")

        self._model = None
        self._vectors: Optional[Any] = None
        self._metadata: List[Dict[str, Any]] = []
        self._data_lock = threading.Lock()

        self._init_model()
        self.load_index()

    @classmethod
    def get_instance(cls) -> "EmbeddingsModule":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = EmbeddingsModule()
        return cls._instance

    def _init_model(self):
        model_name = self.config.get("embedding_model", "all-MiniLM-L6-v2")
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
            self._model = SentenceTransformer(model_name)
        except Exception as exc:
            print(f"[EmbeddingsModule] Notice: sentence-transformers lightweight mode ({exc}). Using TF-IDF/Hash embedding fallback.")
            self._model = None

    def _encode_texts(self, texts: List[str]) -> np.ndarray:
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
                    print(f"[EmbeddingsModule] Could not load index: {exc}")
            self._vectors = np.zeros((0, 384), dtype=np.float32)
            self._metadata = []

    def save_index(self) -> None:
        with self._data_lock:
            if self._vectors is not None:
                np.savez_compressed(self.vector_cache_path, vectors=self._vectors)
                with open(self.meta_cache_path, "w", encoding="utf-8") as f:
                    json.dump(self._metadata, f, indent=2, ensure_ascii=False)

    def build_or_refresh_index(self, force_rebuild: bool = False) -> Dict[str, Any]:
        """Index all preprocessed records, OWASP items, Juliet samples, and multi-language rules."""
        with self._data_lock:
            if not force_rebuild and len(self._metadata) > 0 and self._vectors is not None and len(self._vectors) == len(self._metadata):
                return {"status": "CACHED", "index_size": len(self._metadata)}

            items: List[Dict[str, Any]] = []

            # 1. Load merged_dataset.jsonl
            merged_path = os.path.join(self.data_dir, "merged_dataset.jsonl")
            if os.path.exists(merged_path):
                with open(merged_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            row = json.loads(line)
                            meta = row.get("meta", {})
                            items.append({
                                "text": row.get("prompt", ""),
                                "source": meta.get("source", "Dataset"),
                                "cwe": meta.get("cwe", "Unknown"),
                                "cve": meta.get("cve", "Unknown"),
                                "title": meta.get("title", "Item"),
                                "description": row.get("completion", ""),
                            })
                        except Exception:
                            continue

            # 2. Load taint_rules_dataset.json
            rules_path = os.path.join(self.data_dir, "taint_rules_dataset.json")
            if os.path.exists(rules_path):
                try:
                    with open(rules_path, "r", encoding="utf-8") as f:
                        rdata = json.load(f)
                    for lang, rules in rdata.items():
                        sinks = rules.get("sinks", {})
                        for sink_name, sinfo in sinks.items():
                            items.append({
                                "text": f"Language: {lang} Sink: {sink_name} CWE: {sinfo.get('cwe')} Description: {sinfo.get('description')}",
                                "source": "RuleDataset",
                                "cwe": sinfo.get("cwe", "Unknown"),
                                "cve": "Unknown",
                                "title": f"{lang} {sink_name}",
                                "description": sinfo.get("description", ""),
                            })
                except Exception:
                    pass

            if not items:
                self._vectors = np.zeros((0, 384), dtype=np.float32)
                self._metadata = []
                return {"status": "EMPTY", "index_size": 0}

            texts = [it["text"] for it in items]
            vectors = self._encode_texts(texts)
            self._vectors = vectors
            self._metadata = items

        self.save_index()
        return {"status": "REBUILT", "index_size": len(self._metadata)}

    def encode_query(self, query_text: str) -> np.ndarray:
        return self._encode_texts([query_text])[0]

    def get_index_vectors_and_meta(self) -> Tuple[Optional[np.ndarray], List[Dict[str, Any]]]:
        with self._data_lock:
            return self._vectors, list(self._metadata)
