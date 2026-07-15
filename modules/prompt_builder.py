from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


class PromptBuilderModule:
    """Dynamic Prompt Builder managing system instructions, RAG injection, AST formatting, and token budgeting."""

    DEFAULT_SYSTEM_PROMPT = (
        "You are an expert AI Secure Code Forensics engine powered by fine-tuned LoRA weights and RAG threat intelligence. "
        "Analyze the provided Abstract Syntax Tree (AST) code snippet and retrieved security knowledge. "
        "Output ONLY a valid JSON object with exact keys: 'is_vulnerable' (boolean), 'vulnerability_type' (string/CWE), "
        "'cve' (string), 'cvss_severity' ('Critical'|'High'|'Medium'|'Low'|'Info'), 'confidence' (integer 0-100), "
        "'explanation' (string explaining root cause), 'attack_vector' (string explaining exploitation), and 'suggested_patch' (string)."
    )

    def __init__(self, max_input_tokens: int = 3500):
        self.max_input_tokens = max_input_tokens

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        return len(text) // 4 + 1

    def _truncate_code(self, code: str, max_tokens: int) -> str:
        if self._estimate_tokens(code) <= max_tokens:
            return code
        max_chars = max_tokens * 4
        half = max_chars // 2
        return code[:half] + "\n... [CODE TRUNCATED FOR TOKEN BUDGET] ...\n" + code[-half:]

    def build_verification_prompt(
        self,
        ast_candidate: Dict[str, Any],
        rag_context: Dict[str, Any],
        lang_id: str,
        custom_system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Construct a structured, token-budgeted prompt for vulnerability verification."""
        system_prompt = custom_system_prompt or self.DEFAULT_SYSTEM_PROMPT

        func_name = ast_candidate.get("function_name", "unknown")
        start_line = ast_candidate.get("start_line", 1)
        end_line = ast_candidate.get("end_line", 1)
        snippet = ast_candidate.get("snippet", "")
        candidates = ast_candidate.get("taint_candidates", [])

        # Budget allocation
        sys_tokens = self._estimate_tokens(system_prompt)
        rag_tokens_budget = min(1200, (self.max_input_tokens - sys_tokens) // 3)
        code_tokens_budget = self.max_input_tokens - sys_tokens - rag_tokens_budget - 200

        # Format RAG block
        rag_cwe = rag_context.get("cwe", "Unknown")
        rag_cve = rag_context.get("cve", "Unknown")
        rag_rec = rag_context.get("owasp_recommendation", "")
        rag_refs = ", ".join(rag_context.get("references", []))
        rag_example = rag_context.get("vulnerable_example", "")
        if rag_example:
            rag_example = self._truncate_code(rag_example, 300)

        rag_block = (
            f"=== RETRIEVED THREAT INTELLIGENCE (RAG) ===\n"
            f"Matching CWE: {rag_cwe} | Matching CVE: {rag_cve}\n"
            f"OWASP Recommendation: {rag_rec}\n"
            f"Reference Sources: {rag_refs}\n"
        )
        if rag_example:
            rag_block += f"Example Vulnerable Pattern:\n{rag_example}\n"

        rag_block = self._truncate_code(rag_block, rag_tokens_budget)

        # Format AST & Code block
        code_block = self._truncate_code(snippet, code_tokens_budget)
        ast_summary = (
            f"=== AST TARGET CONTEXT ===\n"
            f"Language: {lang_id}\n"
            f"Function: {func_name} (Lines {start_line}-{end_line})\n"
            f"Detected Taint Candidates: {json.dumps(candidates)}\n\n"
            f"Source Code Snippet:\n```\n{code_block}\n```"
        )

        user_prompt = f"{rag_block}\n\n{ast_summary}\n\nProvide the JSON analysis response now."

        return {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "full_prompt": f"### System:\n{system_prompt}\n\n### Instruction:\n{user_prompt}\n\n### Response:\n",
            "estimated_tokens": sys_tokens + self._estimate_tokens(user_prompt),
        }

    def build_chat_prompt(
        self,
        question: str,
        active_code: str,
        lang_id: str,
        rag_context: Dict[str, Any],
        history: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """Construct grounded prompt for interactive AI Chat questions."""
        system_prompt = (
            "You are an AI Security Assistant pair programming with the user inside the Secure Code Forensics IDE. "
            "Answer the user's question clearly, concisely, and accurately using the provided code snippet and RAG threat intelligence context. "
            "If code rewrite or patch advice is requested, format code cleanly in markdown."
        )

        code_block = self._truncate_code(active_code, 1500)
        rag_rec = rag_context.get("owasp_recommendation", "")
        cwe = rag_context.get("cwe", "Unknown")

        context_header = (
            f"[Grounded Context] Language: {lang_id} | Target CWE: {cwe}\n"
            f"[Threat Advice] {rag_rec}\n"
            f"[Active File Snippet]\n```\n{code_block}\n```\n"
        )

        if history:
            hist_str = "\n".join(f"User: {h.get('user', '')}\nAI: {h.get('ai', '')}" for h in history[-3:])
            context_header += f"\n[Recent Conversation]\n{hist_str}\n"

        user_prompt = f"{context_header}\nUser Question: {question}\n\nAI Answer:"

        return {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "full_prompt": f"### System:\n{system_prompt}\n\n### Instruction:\n{user_prompt}\n",
            "estimated_tokens": self._estimate_tokens(system_prompt + user_prompt),
        }
