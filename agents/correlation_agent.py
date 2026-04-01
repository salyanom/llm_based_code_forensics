from __future__ import annotations

from typing import Any, Dict, List

from services.rag_engine import RAGEngine


class CorrelationAgent:
    def __init__(self, rag_engine: RAGEngine):
        self.rag_engine = rag_engine

    def correlate(self, finding: Dict[str, Any], top_k: int = 3) -> List[Dict[str, Any]]:
        query_text = (
            "Function:\n"
            f"{finding.get('function', '')}\n\n"
            "Detected taint flows:\n"
            f"{finding.get('taint_flows', [])}"
        )
        return self.rag_engine.search(query_text, top_k=top_k)
