from __future__ import annotations

from typing import Any, Dict, Set
from plugins import LanguagePlugin


class JavaScriptPlugin(LanguagePlugin):
    @property
    def language_id(self) -> str:
        return "javascript"

    @property
    def extensions(self) -> Set[str]:
        return {".js", ".jsx", ".mjs", ".cjs"}

    @property
    def tree_sitter_lang_name(self) -> str:
        return "javascript"

    def get_taint_signatures(self) -> Dict[str, Set[str]]:
        return {
            "sources": {
                "req.query", "req.body", "req.params", "req.headers", "process.env",
                "document.location", "document.URL", "window.location", "localStorage.getItem"
            },
            "sinks": {
                "eval", "Function", "setTimeout", "setInterval", "exec", "execSync",
                "spawn", "innerHTML", "outerHTML", "document.write"
            },
            "propagators": {
                "concat", "join", "replace", "split", "slice", "template_string"
            },
            "sanitizers": {
                "encodeURIComponent", "DOMPurify.sanitize", "validator.escape", "xss"
            },
        }

    def is_function_node(self, node: Any) -> bool:
        return node.type in {
            "function_declaration", "generator_function_declaration",
            "function", "arrow_function", "method_definition"
        }

    def extract_function_name(self, node: Any, code_bytes: bytes) -> str:
        for child in node.children:
            if child.type in {"identifier", "property_identifier"}:
                return code_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
        return "anonymous_js_func"
