from typing import Any, Dict, List, Optional, Set
from plugins import LanguagePlugin

class ASTAnalyzer:
    """
    Extracted from modules/parser.py.
    Responsible for deterministic static analysis: AST traversal, symbol extraction, 
    function boundaries, and taint candidate detection.
    """
    def __init__(self, ts_parser):
        self.ts_parser = ts_parser

    def parse_and_extract(
        self, content: str, lang_id: str, plugin: Optional[LanguagePlugin], file_path: str
    ) -> Dict[str, Any]:
        code_bytes = content.encode("utf-8", errors="ignore")
        lines = content.split("\n")

        functions: List[Dict[str, Any]] = []
        imports: List[str] = []
        calls: Set[str] = set()

        # Load rules
        taint_rules: Dict[str, Set[str]] = {}
        if plugin:
            taint_rules = plugin.get_taint_signatures()
        else:
            taint_rules = {"sources": set(), "sinks": set(), "propagators": set(), "sanitizers": set()}

        tree = self.ts_parser.parse(code_bytes, lang_id)
        if tree:
            try:
                root_node = tree.root_node
                self._traverse_node(
                    root_node, code_bytes, lines, lang_id, plugin, taint_rules, functions, imports, calls
                )
            except Exception as e:
                # Fallback to regex/heuristic parsing if tree_sitter fails
                functions = self._heuristic_parse(content, lang_id, taint_rules)
        else:
            functions = self._heuristic_parse(content, lang_id, taint_rules)

        return {
            "file_path": file_path,
            "language": lang_id,
            "functions": functions,
            "imports": list(imports),
            "calls": sorted(list(calls)),
        }

    def _traverse_node(
        self,
        node: Any,
        code_bytes: bytes,
        lines: List[str],
        lang_id: str,
        plugin: Optional[LanguagePlugin],
        taint_rules: Dict[str, Set[str]],
        functions: List[Dict[str, Any]],
        imports: List[str],
        calls: Set[str],
    ) -> None:
        if node.type in {"import_statement", "import_from_statement", "preproc_include"}:
            imp_text = code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore").strip()
            imports.append(imp_text)

        if node.type == "call_expression":
            for child in node.children:
                if child.type in {"identifier", "field_identifier", "property_identifier"}:
                    calls.add(code_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="ignore"))

        if plugin and plugin.is_function_node(node):
            func_name = plugin.extract_function_name(node, code_bytes)
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            snippet = code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

            # Check for taint candidates inside this function block
            candidates = self._detect_taint_candidates(snippet, start_line, taint_rules, lang_id)

            functions.append({
                "function_name": func_name,
                "start_line": start_line,
                "end_line": end_line,
                "snippet": snippet,
                "taint_candidates": candidates,
            })

        for child in node.children:
            self._traverse_node(child, code_bytes, lines, lang_id, plugin, taint_rules, functions, imports, calls)

    def _detect_taint_candidates(
        self, snippet: str, base_line: int, taint_rules: Dict[str, Set[str]], lang_id: str
    ) -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []
        lines = snippet.split("\n")

        sources_found = set()
        sinks_found = []

        for idx, line in enumerate(lines):
            line_num = base_line + idx
            for src in taint_rules.get("sources", set()):
                if src in line:
                    sources_found.add(src)
            for sink in taint_rules.get("sinks", set()):
                if sink in line:
                    # Check if sanitized
                    is_sanitized = any(san in line for san in taint_rules.get("sanitizers", set()))
                    sinks_found.append({
                        "sink": sink,
                        "line_number": line_num,
                        "line_text": line.strip(),
                        "is_sanitized": is_sanitized,
                    })

        for sf in sinks_found:
            candidates.append({
                "sink": sf["sink"],
                "sources_in_scope": list(sources_found),
                "line_number": sf["line_number"],
                "line_text": sf["line_text"],
                "is_sanitized": sf["is_sanitized"],
            })

        return candidates

    def _heuristic_parse(
        self, content: str, lang_id: str, taint_rules: Dict[str, Set[str]]
    ) -> List[Dict[str, Any]]:
        """Fallback lightweight AST extraction when tree-sitter C-binding is not compiled for a specific language."""
        lines = content.split("\n")
        functions: List[Dict[str, Any]] = []
        current_func: Optional[Dict[str, Any]] = None

        for idx, line in enumerate(lines):
            line_num = idx + 1
            stripped = line.strip()
            if not stripped:
                continue

            # Detect function headers
            is_func_start = False
            func_name = "func"
            if lang_id == "python" and stripped.startswith("def "):
                is_func_start = True
                func_name = stripped[4:].split("(")[0].strip()
            elif lang_id in {"c", "cpp", "java", "javascript", "typescript"}:
                if ("(" in stripped and ")" in stripped and ("{" in stripped or stripped.endswith(";"))
                    and not stripped.startswith("if") and not stripped.startswith("for") and not stripped.startswith("while")):
                    is_func_start = True
                    parts = stripped.split("(")
                    if parts:
                        tokens = parts[0].strip().split()
                        if tokens:
                            func_name = tokens[-1]

            if is_func_start:
                if current_func:
                    current_func["end_line"] = line_num - 1
                    current_func["snippet"] = "\n".join(lines[current_func["start_line"] - 1 : current_func["end_line"]])
                    current_func["taint_candidates"] = self._detect_taint_candidates(
                        current_func["snippet"], current_func["start_line"], taint_rules, lang_id
                    )
                    functions.append(current_func)
                current_func = {
                    "function_name": func_name,
                    "start_line": line_num,
                    "end_line": line_num,
                    "snippet": line,
                }
            elif current_func:
                current_func["end_line"] = line_num

        if current_func:
            current_func["end_line"] = len(lines)
            current_func["snippet"] = "\n".join(lines[current_func["start_line"] - 1 : current_func["end_line"]])
            current_func["taint_candidates"] = self._detect_taint_candidates(
                current_func["snippet"], current_func["start_line"], taint_rules, lang_id
            )
            functions.append(current_func)

        # If no functions found, treat entire file as global code block
        if not functions and content.strip():
            functions.append({
                "function_name": "__global_scope__",
                "start_line": 1,
                "end_line": len(lines),
                "snippet": content,
                "taint_candidates": self._detect_taint_candidates(content, 1, taint_rules, lang_id),
            })

        return functions
