from __future__ import annotations
import os
from typing import Any, Dict, List

import numpy as np

from core.knowledge.vector_store.vector_db import VectorDB
from core.knowledge.embeddings.embedding_generator import EmbeddingGenerator

class RAGEngine:
    """Dedicated RAG Engine for semantic vector search and threat intelligence context retrieval."""

    def __init__(self):
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
        self.vector_db = VectorDB(data_dir)
        self.embedding_generator = EmbeddingGenerator()

    def search(self, query_text: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Perform semantic search across vector database and return top-ranked context items."""
        vectors, metadata = self.vector_db.get_index_vectors_and_meta()
        if vectors is None or len(metadata) == 0 or len(vectors) == 0:
            return []

        query_vec = self.embedding_generator.encode_query(query_text)
        query_norm = np.linalg.norm(query_vec)
        if query_norm == 0:
            return []
        query_vec = query_vec / query_norm

        similarities = np.dot(vectors, query_vec)
        top_indices = np.argsort(similarities)[::-1][:top_k]

        results: List[Dict[str, Any]] = []
        for idx in top_indices:
            score = float(similarities[idx])
            if score <= 0.05:
                continue
            item = dict(metadata[idx])
            item["similarity_score"] = round(score, 4)
            results.append(item)

        return results

    def retrieve(self, candidate: Dict[str, Any], lang_id: str) -> Dict[str, Any]:
        """Retrieve structured CWE, CVE, PrimeVul example, and OWASP recommendation given an AST finding."""
        sink = candidate.get("sink", "")
        line_text = candidate.get("line_text", "")
        query = f"Language: {lang_id} Sink: {sink} Code: {line_text}"

        matches = self.search(query, top_k=6)
        cwe = "Unknown"
        cve = "Unknown"
        example_code = ""
        owasp_rec = ""
        references = []

        for m in matches:
            m_cwe = m.get("cwe", "Unknown")
            if cwe == "Unknown" and m_cwe != "Unknown":
                cwe = m_cwe
            m_cve = m.get("cve", "Unknown")
            if cve == "Unknown" and m_cve != "Unknown":
                cve = m_cve

            src = m.get("source", "")
            if src in {"Juliet", "PrimeVul", "CodeSample"} and not example_code:
                example_code = m.get("text", "")
            elif src in {"OWASP", "RuleDataset"} and not owasp_rec:
                owasp_rec = m.get("description", "") or m.get("text", "")

            title = m.get("title", "")
            if title and title not in references:
                references.append(f"[{src}] {title} (Sim: {m.get('similarity_score')})")

        if not owasp_rec:
            owasp_rec = f"Sanitize inputs to '{sink}' and validate untrusted boundaries before execution."

        return {
            "query": query,
            "cwe": cwe,
            "cve": cve,
            "vulnerable_example": example_code,
            "owasp_recommendation": owasp_rec,
            "references": references[:4],
            "top_matches": matches[:3],
        }
