from __future__ import annotations

from typing import Any, Dict, List, Optional
from modules.rag import RAGRetrievalModule


class CorrelationModule:
    """Correlates detected AST taint flow candidates with retrieved RAG threat intelligence."""

    def __init__(self, rag_engine: Optional[RAGRetrievalModule] = None):
        self.rag = rag_engine or RAGRetrievalModule()

    def correlate_file_findings(
        self, file_path: str, lang_id: str, ast_analysis: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Process all functions and taint candidates in a file, correlating each with RAG intelligence."""
        functions = ast_analysis.get("functions", [])
        correlated_items: List[Dict[str, Any]] = []

        for func in functions:
            func_name = func.get("function_name", "unknown")
            candidates = func.get("taint_candidates", [])
            for cand in candidates:
                rag_info = self.rag.retrieve_for_ast_candidate(cand, lang_id)

                correlated = {
                    "file_path": file_path,
                    "language": lang_id,
                    "function_name": func_name,
                    "start_line": cand.get("line_number", func.get("start_line")),
                    "end_line": cand.get("line_number", func.get("end_line")),
                    "sink": cand.get("sink"),
                    "sources_in_scope": cand.get("sources_in_scope", []),
                    "line_text": cand.get("line_text", func.get("snippet", "")),
                    "is_sanitized": cand.get("is_sanitized", False),
                    "full_snippet": func.get("snippet", ""),
                    "rag_context": rag_info,
                }
                correlated_items.append(correlated)

        return correlated_items
