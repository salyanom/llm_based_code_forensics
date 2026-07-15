from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


class VerificationModule:
    """Normalizes CVSS 3.1 metrics, maps canonical CWE/CVE, and computes confidence score (0-100%)."""

    CVSS_MAPPINGS = {
        "CWE-78": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
        "CWE-89": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
        "CWE-95": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
        "CWE-502": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
        "CWE-917": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
        "CWE-120": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8, "High"),
        "CWE-79": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"),
        "CWE-134": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 7.3, "High"),
    }

    @classmethod
    def evaluate_cvss(cls, cwe: str, default_severity: str = "High") -> Tuple[str, float, str]:
        if cwe in cls.CVSS_MAPPINGS:
            return cls.CVSS_MAPPINGS[cwe]
        if default_severity.lower() == "critical":
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.5, "Critical"
        elif default_severity.lower() == "medium":
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.3, "Medium"
        elif default_severity.lower() == "low":
            return "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 2.5, "Low"
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", 7.5, "High"

    @classmethod
    def calculate_confidence(
        cls,
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

    def verify_finding(
        self, correlated_item: Dict[str, Any], llm_response: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Produce verified vulnerability record with normalized severity, CVSS vector, and confidence percentage."""
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

        cvss_vector, cvss_score, severity = self.evaluate_cvss(cwe)
        confidence = self.calculate_confidence(correlated_item, llm_response)

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
            "cwe": cwe,
            "cve": cve,
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "confidence": confidence,
            "is_sanitized": correlated_item["is_sanitized"],
            "correlated_item": correlated_item,
            "llm_response": llm_response or {},
        }
