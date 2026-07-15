from __future__ import annotations

from typing import Any, Dict, Set
from plugins import LanguagePlugin


class CppPlugin(LanguagePlugin):
    @property
    def language_id(self) -> str:
        return "cpp"

    @property
    def extensions(self) -> Set[str]:
        return {".cpp", ".cc", ".cxx", ".hpp", ".hxx"}

    @property
    def tree_sitter_lang_name(self) -> str:
        return "cpp"

    def get_taint_signatures(self) -> Dict[str, Set[str]]:
        return {
            "sources": {
                "std::cin", "cin", "gets", "scanf", "fgets", "recv", "read", "getenv", "recvfrom"
            },
            "sinks": {
                "system", "exec", "execl", "execv", "popen", "strcpy", "sprintf", "printf",
                "memcpy", "std::system", "std::strcpy", "std::sprintf"
            },
            "propagators": {
                "strcpy", "strcat", "memcpy", "std::string::append", "std::string::assign", "std::copy"
            },
            "sanitizers": {
                "snprintf", "strncpy", "std::string::substr", "std::regex_replace"
            },
        }

    def is_function_node(self, node: Any) -> bool:
        return node.type in {"function_definition", "method_definition"}

    def extract_function_name(self, node: Any, code_bytes: bytes) -> str:
        for child in node.children:
            if child.type == "function_declarator":
                for sub in child.children:
                    if sub.type in {"identifier", "qualified_identifier", "field_identifier"}:
                        return code_bytes[sub.start_byte:sub.end_byte].decode("utf-8", errors="ignore")
                return code_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="ignore").split("(")[0]
            elif child.type in {"identifier", "qualified_identifier"}:
                return code_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
        return "unknown_cpp_func"
