from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
from core.scoring import cvss
from core.forensics.agents.categorization_agent import CategorizationAgent
from core.forensics.agents.validation_agent import ValidationAgent

_categorizer = CategorizationAgent()
_validator = ValidationAgent()

class VerificationModule:
    """Legacy wrapper for Verification Module."""

    @classmethod
    def evaluate_cvss(cls, cwe: str, default_severity: str = "High") -> Tuple[str, float, str]:
        return cvss.evaluate_cvss(cwe, default_severity)

    @classmethod
    def calculate_confidence(
        cls,
        correlated_item: Dict[str, Any],
        llm_response: Optional[Dict[str, Any]] = None,
    ) -> int:
        return _validator.calculate_confidence(correlated_item, llm_response)

    def verify_finding(
        self, correlated_item: Dict[str, Any], llm_response: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Produce verified vulnerability record with normalized severity, CVSS vector, and confidence percentage."""
        categorization = _categorizer.categorize(correlated_item, llm_response)
        return _validator.validate(correlated_item, categorization, llm_response)
