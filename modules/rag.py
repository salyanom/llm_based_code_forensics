from __future__ import annotations

from typing import Any, Dict, List
from core.rag.engine import RAGEngine

_engine = RAGEngine()

class RAGRetrievalModule:
    """Legacy RAGRetrievalModule wrapper to maintain backward compatibility."""

    def __init__(self):
        pass

    def search(self, query_text: str, top_k: int = 5) -> List[Dict[str, Any]]:
        return _engine.search(query_text, top_k)

    def retrieve_for_ast_candidate(self, candidate: Dict[str, Any], lang_id: str) -> Dict[str, Any]:
        return _engine.retrieve(candidate, lang_id)
