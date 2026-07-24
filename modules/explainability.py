from __future__ import annotations

from typing import Any, Dict
from core.forensics.agents.explainability_agent import ExplainabilityAgent

_agent = ExplainabilityAgent()

class ExplainabilityModule:
    """Legacy wrapper for Explainability Module."""

    @classmethod
    def generate_evidence_explanation(cls, verified_finding: Dict[str, Any]) -> Dict[str, Any]:
        return _agent.generate_evidence_explanation(verified_finding)
