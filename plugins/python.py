from __future__ import annotations

from typing import Any, Dict, Set
from plugins import LanguagePlugin


class PythonPlugin(LanguagePlugin):
    @property
    def language_id(self) -> str:
        return "python"

    @property
    def extensions(self) -> Set[str]:
        return {".py", ".pyw"}

    @property
    def tree_sitter_lang_name(self) -> str:
        return "python"

    def get_taint_signatures(self) -> Dict[str, Set[str]]:
        return {
            "sources": {
                "input", "read", "recv", "getenv", "os.getenv", "os.environ.get",
                "request.args.get", "request.form.get", "request.get_json", "sys.stdin.read"
            },
            "sinks": {
                "eval", "exec", "os.system", "subprocess.run", "subprocess.call",
                "subprocess.Popen", "popen", "pickle.loads", "yaml.load", "sqlite3.connect",
                "cursor.execute", "open"
            },
            "propagators": {
                "format", "join", "replace", "f-string"
            },
            "sanitizers": {
                "shlex.quote", "html.escape", "bleach.clean", "urllib.parse.quote", "markupsafe.escape"
            },
        }

    def is_function_node(self, node: Any) -> bool:
        return node.type == "function_definition"

    def extract_function_name(self, node: Any, code_bytes: bytes) -> str:
        for child in node.children:
            if child.type == "identifier":
                return code_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
        return "unknown_py_func"
