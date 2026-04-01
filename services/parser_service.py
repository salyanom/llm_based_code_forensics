from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Set

from tree_sitter import Parser
from tree_sitter_languages import get_language


DEFAULT_LANGUAGE_RULES: Dict[str, Dict[str, Set[str]]] = {
    "c": {
        "sources": {
            "gets", "scanf", "fgets", "read", "recv", "getenv", "fgetc", "fread",
        },
        "sinks": {
            "system", "exec", "execl", "execv", "popen", "printf", "fprintf", "sprintf", "strcpy",
        },
        "propagators": {
            "strcpy", "strcat", "memcpy", "strncpy", "memmove",
        },
        "sanitizers": {
            "snprintf", "strncpy", "fgets",
        },
    },
    "python": {
        "sources": {
            "input", "read", "recv", "getenv", "open",
        },
        "sinks": {
            "eval", "exec", "os.system", "subprocess.run", "subprocess.call", "subprocess.Popen", "popen",
        },
        "propagators": {
            "format", "join", "replace",
        },
        "sanitizers": {
            "shlex.quote", "html.escape", "bleach.clean",
        },
    },
}


_RE_C_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_RE_C_LINE_COMMENT = re.compile(r"//[^\n]*")
_RE_PY_LINE_COMMENT = re.compile(r"#[^\n]*")


class ParserService:
    # Backward-compatible aggregate rule view.
    RULES = {
        "sources": set().union(*[rule["sources"] for rule in DEFAULT_LANGUAGE_RULES.values()]),
        "sinks": set().union(*[rule["sinks"] for rule in DEFAULT_LANGUAGE_RULES.values()]),
        "propagators": set().union(*[rule["propagators"] for rule in DEFAULT_LANGUAGE_RULES.values()]),
        "sanitizers": set().union(*[rule["sanitizers"] for rule in DEFAULT_LANGUAGE_RULES.values()]),
    }

    def __init__(self):
        self.languages = {
            "c": get_language("c"),
            "python": get_language("python"),
        }
        self.language_rules = self._load_language_rules("taint_rules.json")

    @staticmethod
    def _find_rules_path(file_name: str) -> Optional[str]:
        candidates = [
            file_name,
            os.path.join(os.getcwd(), file_name),
            os.path.join(os.path.dirname(os.path.dirname(__file__)), file_name),
        ]
        for path in candidates:
            if os.path.isfile(path):
                return path
        return None

    @staticmethod
    def _strip_comments(text: str, language: str) -> str:
        if language == "c":
            text = _RE_C_BLOCK_COMMENT.sub(" ", text)
            text = _RE_C_LINE_COMMENT.sub("", text)
        elif language == "python":
            text = _RE_PY_LINE_COMMENT.sub("", text)
        return text

    def _load_language_rules(self, rules_file: str) -> Dict[str, Dict[str, Set[str]]]:
        merged: Dict[str, Dict[str, Set[str]]] = {
            lang: {kind: set(values) for kind, values in rules.items()}
            for lang, rules in DEFAULT_LANGUAGE_RULES.items()
        }

        rules_path = self._find_rules_path(rules_file)
        if not rules_path:
            return merged

        try:
            with open(rules_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception:
            return merged

        if not isinstance(payload, dict):
            return merged

        categories = {"sources", "sinks", "propagators", "sanitizers"}

        # Legacy flat schema applies to C rules.
        if any(key in payload for key in categories):
            for key in categories:
                values = payload.get(key)
                if isinstance(values, list):
                    merged["c"][key].update(
                        str(item).strip() for item in values if str(item).strip()
                    )

        # Language-specific schema.
        for language in ("c", "python"):
            language_block = payload.get(language)
            if not isinstance(language_block, dict):
                continue
            for key in categories:
                values = language_block.get(key)
                if isinstance(values, list):
                    merged[language][key].update(
                        str(item).strip() for item in values if str(item).strip()
                    )

        return merged

    @staticmethod
    def _clean_var(token: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_]", "", token or "")

    @staticmethod
    def _extract_identifiers(text: str) -> List[str]:
        return re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", text or "")

    @staticmethod
    def _detect_language(file_path: str) -> Optional[str]:
        lower = file_path.lower()
        if lower.endswith((".c", ".h")):
            return "c"
        if lower.endswith(".py"):
            return "python"
        return None

    def _new_parser(self, language: str) -> Parser:
        parser = Parser()
        parser.set_language(self.languages[language])
        return parser

    def extract_functions_from_folder(self, folder: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for root, _, files in os.walk(folder):
            for file_name in files:
                full_path = os.path.join(root, file_name)
                if self._detect_language(full_path) is None:
                    continue
                findings.extend(self.extract_functions_from_file(full_path))
        return findings

    def analyze_code_snippet(self, code_text: str, language: str = "c") -> Dict[str, Any]:
        if language not in self.languages:
            return {"taint_flows": []}

        code = code_text.encode("utf-8", errors="ignore")
        parser = self._new_parser(language)
        tree = parser.parse(code)

        root = tree.root_node
        target = None
        for child in root.children:
            if child.type in {"function_definition", "function_declaration"}:
                target = child
                break

        if target is None:
            target = root

        flows = self.detect_taint_flow(target, code, language=language)
        return {"taint_flows": flows}

    def extract_functions_from_file(self, file_path: str) -> List[Dict[str, Any]]:
        language = self._detect_language(file_path)
        if language is None:
            return []

        with open(file_path, "rb") as handle:
            code = handle.read()

        parser = self._new_parser(language)
        tree = parser.parse(code)
        extracted: List[Dict[str, Any]] = []

        def get_text(node) -> str:
            return code[node.start_byte:node.end_byte].decode(errors="ignore")

        def extract_name(node) -> str:
            if language == "c":
                for child in node.children:
                    if child.type == "function_declarator":
                        for sub in child.children:
                            if sub.type == "identifier":
                                return get_text(sub)
            elif language == "python":
                for child in node.children:
                    if child.type == "identifier":
                        return get_text(child)
            return "unknown"

        def traverse(node):
            is_function = (language == "c" and node.type == "function_definition") or (
                language == "python" and node.type == "function_definition"
            )

            if is_function:
                func_text = get_text(node)
                taint_flows = self.detect_taint_flow(node, code, language=language)
                extracted.append(
                    {
                        "file": os.path.basename(file_path),
                        "path": file_path,
                        "language": language,
                        "function_name": extract_name(node),
                        "start_line": node.start_point[0] + 1,
                        "taint_flows": taint_flows,
                        "function": func_text,
                    }
                )

            for child in node.children:
                traverse(child)

        traverse(tree.root_node)
        return extracted

    def detect_taint_flow(
        self,
        node,
        code: bytes,
        parameters: Optional[List[str]] = None,
        language: str = "c",
    ) -> List[Dict[str, Any]]:
        rules = self.language_rules.get(language, self.language_rules["c"])
        tainted_vars = set(parameters or [])
        sanitized_vars = set()
        flows: List[Dict[str, Any]] = []
        seen_events = set()
        function_text = code[node.start_byte:node.end_byte].decode(errors="ignore")
        function_text_no_comments = self._strip_comments(function_text, language)
        buffer_sizes: Dict[str, int] = {}

        if language == "c":
            for match in re.finditer(r"\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]", function_text_no_comments):
                buffer_sizes[match.group(1)] = int(match.group(2))

        def get_text(n) -> str:
            return code[n.start_byte:n.end_byte].decode(errors="ignore")

        def extract_args(text: str) -> List[str]:
            return [self._clean_var(item) for item in self._extract_identifiers(text)]

        def mark_flow(flow_type: str, function: str, variable: str, current_line: int, note: str = ""):
            event_key = (flow_type, function, variable, current_line)
            if event_key in seen_events:
                return
            seen_events.add(event_key)
            flows.append(
                {
                    "type": flow_type,
                    "function": function,
                    "variable": variable,
                    "line": current_line,
                    "note": note,
                }
            )

        def process_assignment(expr_node):
            expr_text = get_text(expr_node)
            line = expr_node.start_point[0] + 1
            if "=" not in expr_text:
                return
            lhs, rhs = expr_text.split("=", 1)
            lhs_var = self._clean_var(lhs)
            rhs_vars = set(extract_args(rhs))

            call_match = re.search(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\((.*)\)", rhs)
            if call_match:
                called_fn = call_match.group(1)
                call_args = [self._clean_var(v) for v in self._extract_identifiers(call_match.group(2))]
                if any(arg in tainted_vars for arg in call_args):
                    tainted_vars.add(lhs_var)
                    mark_flow("INTERPROC_RETURN", called_fn, lhs_var, line, "tainted argument flows through return value")

            if any(var in tainted_vars for var in rhs_vars):
                tainted_vars.add(lhs_var)
                mark_flow("REASSIGN_TAINT", "assignment", lhs_var, line, "taint propagated by assignment")
            elif lhs_var in tainted_vars:
                tainted_vars.discard(lhs_var)
                mark_flow("REASSIGN_CLEAN", "assignment", lhs_var, line, "taint cleared by reassignment")

            if any(s in rhs for s in rules["sanitizers"]):
                sanitized_vars.add(lhs_var)
                mark_flow("SANITIZED", "assignment", lhs_var, line, "sanitizer call detected")

            if re.search(r"\b\w+\s*\+\s*\w+\b", rhs):
                mark_flow("POTENTIAL_INT_OVERFLOW", "assignment", lhs_var, line, "arithmetic operation may overflow")

        def traverse(n, in_sanitization_guard: bool = False):
            current_line = n.start_point[0] + 1

            if n.type in {"assignment_expression"}:
                process_assignment(n)

            if n.type in {"if_statement"}:
                condition_text = get_text(n)
                guard_has_sanitizer = any(s in condition_text for s in rules["sanitizers"])
                for child in n.children:
                    traverse(child, in_sanitization_guard=guard_has_sanitizer or in_sanitization_guard)
                return

            if n.type == "return_statement":
                return_text = get_text(n)
                return_vars = extract_args(return_text)
                for var in return_vars:
                    if var in tainted_vars:
                        mark_flow("RETURN_TAINT", "return", var, current_line, "tainted value returned")

            if n.type == "call_expression":
                func_name = ""
                args: List[str] = []
                call_text = get_text(n)

                for child in n.children:
                    if child.type in {"identifier", "attribute"}:
                        func_name = get_text(child)
                    if child.type in {"argument_list", "parameters"}:
                        args = extract_args(get_text(child))

                if not func_name:
                    call_candidates = self._extract_identifiers(call_text)
                    if call_candidates:
                        func_name = call_candidates[0]
                        args = [self._clean_var(v) for v in call_candidates[1:]]

                if func_name in rules["sources"]:
                    for arg in args:
                        tainted_vars.add(arg)
                        mark_flow("SOURCE", func_name, arg, current_line)

                elif func_name in rules["propagators"]:
                    if len(args) >= 2 and args[1] in tainted_vars:
                        tainted_vars.add(args[0])
                        # Avoid double-reporting for strcpy where specific events are emitted below.
                        if not (language == "c" and func_name == "strcpy"):
                            mark_flow("PROPAGATOR", func_name, args[0], current_line)

                elif func_name in rules["sanitizers"]:
                    if args:
                        sanitized_vars.add(args[0])
                        mark_flow("SANITIZED", func_name, args[0], current_line)

                elif func_name in rules["sinks"]:
                    for arg in args:
                        if arg in tainted_vars:
                            if in_sanitization_guard or arg in sanitized_vars:
                                mark_flow("SINK_GUARDED", func_name, arg, current_line, "guarded/sanitized")
                            else:
                                mark_flow("SINK", func_name, arg, current_line)

                if language == "c" and func_name == "strcpy" and len(args) >= 2:
                    dest = args[0]
                    src = args[1]
                    dest_size = buffer_sizes.get(dest)
                    note = "unbounded copy"
                    if dest_size is not None:
                        note = f"destination buffer '{dest}' size={dest_size}; source length unbounded"
                    mark_flow("UNBOUNDED_COPY", func_name, dest, current_line, note)
                    if src in tainted_vars:
                        mark_flow("BUFFER_OVERFLOW_RISK", func_name, dest, current_line, "tainted source copied via strcpy")

                if language == "c" and func_name == "sprintf" and len(args) >= 2:
                    dest = args[0]
                    mark_flow("UNBOUNDED_WRITE", func_name, dest, current_line, "use snprintf instead of sprintf")
                    if any(arg in tainted_vars for arg in args[1:]):
                        tainted_vars.add(dest)
                        mark_flow("PROPAGATOR", func_name, dest, current_line, "tainted data formatted into destination buffer")

                if language == "c" and func_name == "gets" and args:
                    mark_flow("UNBOUNDED_READ", func_name, args[0], current_line, "gets has no bounds checking")

                if language == "c" and func_name in {"printf", "fprintf", "sprintf"} and args:
                    first_arg = args[0]
                    if first_arg not in {"stdout", "stderr"}:
                        raw_first_segment = call_text.split("(", 1)[1].split(",", 1)[0] if "(" in call_text else ""
                        if "\"" not in raw_first_segment and "'" not in raw_first_segment:
                            mark_flow("FORMAT_STRING_RISK", func_name, first_arg, current_line, "non-literal format string")

                if language == "c" and func_name in {"malloc", "calloc", "realloc", "free"}:
                    if func_name == "free" and args:
                        mark_flow("MEMORY_RELEASE", func_name, args[0], current_line, "ensure pointer not used after free")
                    else:
                        mark_flow("MEMORY_ALLOC", func_name, args[0] if args else "ptr", current_line, "validate allocation result")

            for child in n.children:
                traverse(child, in_sanitization_guard=in_sanitization_guard)

        traverse(node)
        return flows
