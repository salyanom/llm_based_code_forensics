from typing import Any, Dict, Optional
from core.scoring import cvss

class CategorizationAgent:
    """Classifies vulnerabilities by mapping LLM findings and RAG evidence to CWE, severity, and CVSS vectors."""

    def categorize(self, correlated_item: Dict[str, Any], llm_response: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Determine structured vulnerability classification including CWE and CVSS scores."""
        rag_ctx = correlated_item.get("rag_context", {})
        cwe = rag_ctx.get("cwe", "Unknown")
        cve = rag_ctx.get("cve", "Unknown")

        if llm_response and isinstance(llm_response, dict):
            if llm_response.get("vulnerability_type") and llm_response["vulnerability_type"] != "Check Explanation":
                cwe = llm_response["vulnerability_type"]
            elif llm_response.get("cwe") and llm_response["cwe"] != "Unknown":
                cwe = llm_response["cwe"]
            elif llm_response.get("vulnerability") and llm_response["vulnerability"] != "Check Explanation":
                cwe = llm_response["vulnerability"]

            if llm_response.get("cve") and llm_response["cve"] != "Unknown":
                cve = llm_response["cve"]

        cvss_vector, cvss_score, severity = cvss.evaluate_cvss(cwe)

        return {
            "cwe": cwe,
            "cve": cve,
            "cvss_vector": cvss_vector,
            "cvss_score": cvss_score,
            "severity": severity
        }
