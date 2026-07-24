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
        
        from core.parser.tree_sitter_parser import TreeSitterParser
        self.ts_parser = TreeSitterParser(self.registry)

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

        from core.scanner.repository_scanner import RepositoryScanner
        scanner = RepositoryScanner(self.config)
        
        valid_files = scanner.get_files_to_scan(folder_path)
        for file_path in valid_files:
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
        from core.scanner.language_detector import LanguageDetector
        detector = LanguageDetector(self.registry)
        lang_id, plugin = detector.detect(file_path)

        from core.parser.ast_analyzer import ASTAnalyzer
        analyzer = ASTAnalyzer(self.ts_parser)
        
        analysis = analyzer.parse_and_extract(content, lang_id, plugin, file_path)
        analysis["from_cache"] = False
        analysis["content_hash"] = content_hash

        self._cache[file_path] = {
            "mtime": mtime,
            "content_hash": content_hash,
            "analysis": analysis,
        }
        return analysis

