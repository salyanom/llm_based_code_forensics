from __future__ import annotations

from typing import Any, Dict, Optional
from core.forensics.agents.advisory_refactoring_agent import AdvisoryRefactoringAgent
from modules.parser import ASTParserModule

class PatchGenerationModule:
    """Legacy wrapper for Patch Generation Module."""

    def __init__(self, parser_module: Optional[ASTParserModule] = None):
        self._agent = AdvisoryRefactoringAgent(parser_module)

    @staticmethod
    def generate_unified_diff(
        file_path: str,
        original_code: str,
        patched_code: str,
    ) -> str:
        return AdvisoryRefactoringAgent.generate_unified_diff(file_path, original_code, patched_code)

    def generate_patch_for_finding(
        self, verified_finding: Dict[str, Any], file_content: Optional[str] = None
    ) -> Dict[str, Any]:
        return self._agent.generate_patch_for_finding(verified_finding, file_content)
