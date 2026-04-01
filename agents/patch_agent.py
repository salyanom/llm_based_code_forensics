from __future__ import annotations

from typing import Any, Dict

from services.llm_service import LLMService
from services.parser_service import ParserService


class PatchAgent:
    def __init__(self, llm_service: LLMService, parser_service: ParserService):
        self.llm_service = llm_service
        self.parser_service = parser_service

    def generate_patch(self, code_snippet: str, vulnerability_type: str) -> str:
        return self.llm_service.generate_patch(code_snippet, vulnerability_type)

    def verify_patch(self, original_code: str, patched_code: str, language: str = "c") -> Dict[str, Any]:
        original = self.parser_service.analyze_code_snippet(original_code, language=language)
        patched = self.parser_service.analyze_code_snippet(patched_code, language=language)

        unsafe_apis = ["gets(", "strcpy(", "sprintf(", "system(", "scanf("]
        safer_apis = ["fgets(", "strncpy(", "snprintf(", "memcpy("]
        sanitizer_keywords = ["validate", "sanitize", "bounds", "length", "len", "size"]

        def tainted_sink_count(flows: list) -> int:
            return sum(1 for f in flows if f.get("type") == "SINK")

        def count_tokens(text: str, tokens: list) -> int:
            return sum(text.count(token) for token in tokens)

        original_count = tainted_sink_count(original.get("taint_flows", []))
        patched_count = tainted_sink_count(patched.get("taint_flows", []))

        original_unsafe = count_tokens(original_code, unsafe_apis)
        patched_unsafe = count_tokens(patched_code, unsafe_apis)

        safer_added = count_tokens(patched_code, safer_apis) > count_tokens(original_code, safer_apis)
        sanitizer_added = any(keyword in patched_code.lower() for keyword in sanitizer_keywords)
        snprintf_upgrade = "sprintf(" in original_code and "snprintf(" in patched_code

        checks = {
            "tainted_sinks_reduced": patched_count < original_count,
            "unsafe_api_reduced": patched_unsafe < original_unsafe,
            "safer_api_added": safer_added,
            "sanitizer_or_bounds_added": sanitizer_added,
            "sprintf_to_snprintf": snprintf_upgrade,
        }

        true_checks = sum(1 for value in checks.values() if value)
        status = "FAILED"
        if checks["tainted_sinks_reduced"] or (checks["unsafe_api_reduced"] and checks["safer_api_added"]):
            status = "VALIDATED"
        elif true_checks >= 2:
            status = "NO_EVIDENCE"

        return {
            "original_tainted_sinks": original_count,
            "patched_tainted_sinks": patched_count,
            "original_unsafe_api_count": original_unsafe,
            "patched_unsafe_api_count": patched_unsafe,
            "checks": checks,
            "status": status,
            "valid": status == "VALIDATED",
        }
