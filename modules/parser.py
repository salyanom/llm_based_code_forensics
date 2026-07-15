from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Set, Tuple

from config_manager import ConfigManager
from plugins import get_plugin_registry, LanguagePlugin


class ASTParserModule:
    """Multi-language AST Parser & Incremental Scanning Engine."""

    def __init__(self, cache_dir: Optional[str] = None):
        self.config = ConfigManager.get_instance()
        self.registry = get_plugin_registry()
        self.cache_dir = cache_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cache"
        )
        os.makedirs(self.cache_dir, exist_ok=True)
        self.cache_file = os.path.join(self.cache_dir, "incremental_ast_cache.json")
        self._cache: Dict[str, Dict[str, Any]] = self._load_cache()
        self._parsers: Dict[str, Any] = {}
        self._init_tree_sitter()

    def _load_cache(self) -> Dict[str, Dict[str, Any]]:
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_cache(self) -> None:
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2, ensure_ascii=False)
        except Exception as exc:
            print(f"[ASTParserModule] Warning: Could not save cache: {exc}")

    def _init_tree_sitter(self):
        try:
            from tree_sitter import Parser  # type: ignore
            from tree_sitter_languages import get_language  # type: ignore
            for lang_id in self.registry.list_languages():
                plugin = self.registry.get_plugin_by_id(lang_id)
                if plugin:
                    try:
                        ts_lang = get_language(plugin.tree_sitter_lang_name)
                        parser = Parser()
                        if hasattr(parser, "set_language"):
                            parser.set_language(ts_lang)
                        elif hasattr(parser, "language"):
                            parser.language = ts_lang
                        self._parsers[lang_id] = parser
                    except Exception as e:
                        # Fallback or missing language build
                        pass
        except Exception as exc:
            print(f"[ASTParserModule] Notice: tree_sitter initialized in lightweight / fallback mode: {exc}")

    @staticmethod
    def _compute_hash(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

    def scan_project(self, folder_path: str, force_reparse: bool = False) -> Dict[str, Any]:
        """Recursively scan a project directory respecting ignore rules and incremental cache."""
        folder_path = os.path.abspath(folder_path)
        if not os.path.isdir(folder_path):
            return {"error": f"Directory not found: {folder_path}"}

        results: Dict[str, Any] = {
            "folder_path": folder_path,
            "files_scanned": 0,
            "files_from_cache": 0,
            "files_reparsed": 0,
            "functions_found": 0,
            "taint_candidates_found": 0,
            "file_results": {},
        }

        for root, dirs, files in os.walk(folder_path):
            # Filter out ignored directories in place
            dirs[:] = [d for d in dirs if not self.config.is_ignored_dir(d)]

            for file_name in files:
                ext = os.path.splitext(file_name)[1].lower()
                if not self.config.is_supported_extension(ext):
                    continue

                file_path = os.path.join(root, file_name)
                try:
                    file_size = os.path.getsize(file_path)
                    if file_size > self.config.get("max_file_size_bytes", 1048576):
                        continue
                except OSError:
                    continue

                file_res = self.scan_file_incremental(file_path, force_reparse=force_reparse)
                results["files_scanned"] += 1
                if file_res.get("from_cache"):
                    results["files_from_cache"] += 1
                else:
                    results["files_reparsed"] += 1

                funcs = file_res.get("functions", [])
                results["functions_found"] += len(funcs)
                for f in funcs:
                    if f.get("taint_candidates"):
                        results["taint_candidates_found"] += len(f["taint_candidates"])

                results["file_results"][file_path] = file_res

        self._save_cache()
        return results

    def scan_file_incremental(self, file_path: str, force_reparse: bool = False) -> Dict[str, Any]:
        """Parse a single file or instantly return cached AST analysis if unchanged."""
        file_path = os.path.abspath(file_path)
        try:
            mtime = os.path.getmtime(file_path)
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as exc:
            return {"file_path": file_path, "error": str(exc), "from_cache": False}

        content_hash = self._compute_hash(content)

        # Check incremental cache
        if not force_reparse and file_path in self._cache:
            cached = self._cache[file_path]
            if cached.get("content_hash") == content_hash and cached.get("mtime") == mtime:
                cached_res = dict(cached.get("analysis", {}))
                cached_res["from_cache"] = True
                return cached_res

        # Re-parse file
        ext = os.path.splitext(file_path)[1].lower()
        plugin = self.registry.get_plugin_by_extension(ext)
        lang_id = plugin.language_id if plugin else "unknown"

        analysis = self._parse_and_extract(content, lang_id, plugin, file_path)
        analysis["from_cache"] = False
        analysis["content_hash"] = content_hash

        self._cache[file_path] = {
            "mtime": mtime,
            "content_hash": content_hash,
            "analysis": analysis,
        }
        return analysis

    def _parse_and_extract(
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

        parser = self._parsers.get(lang_id)
        if parser:
            try:
                tree = parser.parse(code_bytes)
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
