from __future__ import annotations
import os
import threading
from typing import Any, Dict, List, Optional, Tuple
import numpy as np # type: ignore

from core.knowledge.embeddings.embedding_generator import EmbeddingGenerator
from core.knowledge.vector_store.vector_db import VectorDB
from core.knowledge.threat.preprocessor import ThreatPreprocessor

class EmbeddingsModule:
    """
    Compatibility layer for EmbeddingsModule.
    Delegates to Phase 2A components (EmbeddingGenerator, VectorDB, ThreatPreprocessor).
    """
    _instance: Optional["EmbeddingsModule"] = None
    _lock = threading.Lock()

    def __init__(self):
        self.root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.data_dir = os.path.join(self.root_dir, "data")
        self.knowledge_dir = os.path.join(self.root_dir, "knowledge")
        
        self.vector_db = VectorDB(self.data_dir)
        self.generator = EmbeddingGenerator()
        self.preprocessor = ThreatPreprocessor(self.knowledge_dir)

    @classmethod
    def get_instance(cls) -> "EmbeddingsModule":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = EmbeddingsModule()
        return cls._instance

    def build_or_refresh_index(self, force_rebuild: bool = False) -> Dict[str, Any]:
        """Build the runtime knowledge base using the ThreatPreprocessor."""
        if not force_rebuild and self.vector_db.get_index_size() > 0:
            return {"status": "CACHED", "index_size": self.vector_db.get_index_size()}

        items: List[Dict[str, Any]] = []

        # 1. Load Threat Feeds (NVD, OWASP)
        threat_records = self.preprocessor.load_and_preprocess()
        for rec in threat_records:
            items.append({
                "text": rec.get("cleaned_code") or rec.get("description", ""),
                "source": rec.get("source", "ThreatFeed"),
                "cwe": rec.get("cwe", "Unknown"),
                "cve": rec.get("cve", "Unknown"),
                "title": rec.get("title", "Item"),
                "description": rec.get("description", ""),
            })

        # 2. Load Taint Rules as Knowledge
        rules_path = os.path.join(self.data_dir, "taint_rules_dataset.json")
        if os.path.exists(rules_path):
            import json
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
            return {"status": "EMPTY", "index_size": 0}

        texts = [it["text"] for it in items]
        vectors = self.generator.encode(texts)
        self.vector_db.update_index(vectors, items)

        return {"status": "REBUILT", "index_size": self.vector_db.get_index_size()}

    def encode_query(self, query_text: str) -> np.ndarray:
        return self.generator.encode_query(query_text)

    def get_index_vectors_and_meta(self) -> Tuple[Optional[np.ndarray], List[Dict[str, Any]]]:
        return self.vector_db.get_index_vectors_and_meta()
