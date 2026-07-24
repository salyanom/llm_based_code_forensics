from typing import Any, Dict, Optional

class ValidationAgent:
    """Validates findings, reduces false positives, and calculates strict confidence scores."""

    def calculate_confidence(
        self,
        correlated_item: Dict[str, Any],
        llm_response: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Compute strict confidence percentage (0-100) combining AST evidence, RAG match, and LLM confirmation."""
        base_score = 65
        is_sanitized = correlated_item.get("is_sanitized", False)
        sources_in_scope = correlated_item.get("sources_in_scope", [])
        rag_context = correlated_item.get("rag_context", {})

        if is_sanitized:
            base_score -= 50
        else:
            base_score += 10

        if len(sources_in_scope) > 0:
            base_score += 15

        matches = rag_context.get("top_matches", [])
        if matches:
            top_sim = matches[0].get("similarity_score", 0.0)
            if top_sim >= 0.5:
                base_score += 10

        if llm_response and isinstance(llm_response, dict):
            if llm_response.get("is_vulnerable") is True:
                base_score += 10
                llm_conf = llm_response.get("confidence")
                if isinstance(llm_conf, int):
                    base_score = (base_score + min(max(llm_conf, 0), 100)) // 2
            elif llm_response.get("is_vulnerable") is False:
                base_score -= 30

        return min(max(base_score, 5), 98)

    def validate(
        self, 
        correlated_item: Dict[str, Any], 
        categorization: Dict[str, Any],
        llm_response: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Combine categorization with confidence scoring to validate the finding."""
        confidence = self.calculate_confidence(correlated_item, llm_response)
        
        severity = categorization["severity"]
        cvss_score = categorization["cvss_score"]
        
        # If confidence drops very low due to sanitization or LLM rejection, adjust severity
        if confidence < 35:
            severity = "Info"
            cvss_score = min(cvss_score, 2.0)
            
        return {
            "file_path": correlated_item["file_path"],
            "language": correlated_item["language"],
            "function_name": correlated_item["function_name"],
            "start_line": correlated_item["start_line"],
            "end_line": correlated_item["end_line"],
            "sink": correlated_item["sink"],
            "line_text": correlated_item["line_text"],
            "is_sanitized": correlated_item.get("is_sanitized", False),
            "sources_in_scope": correlated_item.get("sources_in_scope", []),
            "cwe": categorization["cwe"],
            "cve": categorization["cve"],
            "severity": severity,
            "cvss_vector": categorization["cvss_vector"],
            "cvss_score": cvss_score,
            "confidence": confidence,
            "llm_response": llm_response,
            "correlated_item": correlated_item,
        }
