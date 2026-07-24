from __future__ import annotations

from typing import Any, Dict, List, Optional
from core.llm.prompts import verification, explanation

class PromptBuilderModule:
    """Legacy wrapper for Prompt Builder."""

    def __init__(self, max_input_tokens: int = 3500):
        self.max_input_tokens = max_input_tokens

    def build_verification_prompt(
        self,
        ast_candidate: Dict[str, Any],
        rag_context: Dict[str, Any],
        lang_id: str,
        custom_system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        return verification.build_verification_prompt(
            ast_candidate, rag_context, lang_id, self.max_input_tokens, custom_system_prompt
        )

    def build_chat_prompt(
        self,
        question: str,
        active_code: str,
        lang_id: str,
        rag_context: Dict[str, Any],
        history: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        return explanation.build_chat_prompt(
            question, active_code, lang_id, rag_context, history
        )
