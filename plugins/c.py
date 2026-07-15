from __future__ import annotations

from typing import Any, Dict, Set
from plugins import LanguagePlugin


class CPlugin(LanguagePlugin):
    @property
    def language_id(self) -> str:
        return "c"

    @property
    def extensions(self) -> Set[str]:
        return {".c", ".h"}

    @property
    def tree_sitter_lang_name(self) -> str:
        return "c"

    def get_taint_signatures(self) -> Dict[str, Set[str]]:
        return {
            "sources": {
                "gets", "scanf", "fgets", "fgetc", "fread", "recv", "read",
                "getenv", "recvfrom", "recvmsg", "getchar"
            },
            "sinks": {
                "system", "exec", "execl", "execle", "execlp", "execv", "execve", "execvp",
                "popen", "strcpy", "sprintf", "vsprintf", "printf", "fprintf", "strcat"
            },
            "propagators": {
                "strcpy", "strcat", "memcpy", "strncpy", "memmove", "strdup", "strndup"
            },
            "sanitizers": {
                "strncpy", "snprintf", "vsnprintf", "fgets", "strlcpy", "strlcat"
            },
        }

    def is_function_node(self, node: Any) -> bool:
        return node.type == "function_definition"

    def extract_function_name(self, node: Any, code_bytes: bytes) -> str:
        for child in node.children:
            if child.type == "function_declarator":
                for sub in child.children:
                    if sub.type == "identifier":
                        return code_bytes[sub.start_byte:sub.end_byte].decode("utf-8", errors="ignore")
                # Fallback to declarator text
                return code_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="ignore").split("(")[0]
        return "unknown_c_func"
