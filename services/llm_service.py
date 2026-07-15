from __future__ import annotations

import json
from typing import Any, Dict, List


class LLMService:
    def __init__(self, model_name: str = "deepseek-coder:6.7b"):
        self.model_name = model_name

    def _chat(self, system_prompt: str, user_prompt: str, temperature: float = 0.1) -> str:
        import ollama

        response = ollama.chat(
            model=self.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            options={"temperature": temperature},
        )
        return response["message"]["content"]

    @staticmethod
    def _extract_json_array(content: str) -> List[Dict[str, Any]]:
        start = content.find("[")
        end = content.rfind("]")
        if start != -1 and end != -1 and end > start:
            try:
                payload = json.loads(content[start:end + 1])
                if isinstance(payload, list):
                    return [item for item in payload if isinstance(item, dict)]
            except Exception:
                pass
        
        # Check if single dict was returned instead of array
        start_obj = content.find("{")
        end_obj = content.rfind("}")
        if start_obj != -1 and end_obj != -1 and end_obj > start_obj:
            try:
                payload = json.loads(content[start_obj:end_obj + 1])
                if isinstance(payload, dict):
                    return [payload]
            except Exception:
                pass
        return []

    def analyze_vulnerabilities(self, finding: Dict[str, Any], rag_matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        system_prompt = "You are a senior application security analyst. Output JSON array only."

        user_prompt = f"""
Analyze the function for vulnerabilities.

TARGET_FUNCTION_NAME: {finding.get("function_name")}
FILE: {finding.get("file")}
LANGUAGE: {finding.get("language")}

TARGET_CODE:
{finding.get("function", "")}

STATIC_TAINT_EVIDENCE:
{json.dumps(finding.get("taint_flows", []), ensure_ascii=False)}

RAG_MATCHES:
{json.dumps(rag_matches, ensure_ascii=False)}

Return JSON array. For each vulnerability return keys:
- vulnerability
- line (integer)
- cwe
- cve
- threat_intel_match (true/false)
- explanation
- cvss_metrics object with keys:
  attack_vector, attack_complexity, privileges_required, user_interaction, scope,
  confidentiality_impact, integrity_impact, availability_impact

If none are found, return []
"""

        content = self._chat(system_prompt, user_prompt, temperature=0.1)
        return self._extract_json_array(content)

    def generate_patch(self, code_snippet: str, vulnerability_type: str) -> str:
        system_prompt = "You are a secure coding assistant. Return only patched code."
        user_prompt = f"""
Rewrite this function securely to mitigate: {vulnerability_type}

Requirements:
- Keep the same function behavior as much as possible.
- Replace unsafe APIs with safer alternatives.
- Add input validation and bounds checks.
- Return only code.

CODE:
{code_snippet}
"""
        return self._chat(system_prompt, user_prompt, temperature=0.0).strip()

    def ask_security_assistant(self, prompt: str, scan_context: Dict[str, Any] | None = None) -> str:
        system_prompt = (
            "You are a senior application security consultant. "
            "Give professional, practical, concise answers. "
            "When scan context is provided, ground your response in that context, "
            "highlight risk priority, and provide actionable next steps."
        )

        context_json = json.dumps(scan_context or {}, ensure_ascii=False)
        user_prompt = f"""
USER_QUESTION:
{prompt}

SCAN_CONTEXT_JSON:
{context_json}

Respond with:
1) Short answer
2) Key observations
3) Recommended next actions
"""
        return self._chat(system_prompt, user_prompt, temperature=0.1).strip()
