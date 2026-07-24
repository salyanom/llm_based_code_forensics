from typing import Any, Dict, Optional

class TreeSitterParser:
    """
    Extracted from modules/parser.py.
    Initializes tree-sitter parsers for supported languages and provides raw AST parsing.
    """
    def __init__(self, registry):
        self.registry = registry
        self._parsers: Dict[str, Any] = {}
        self._init_tree_sitter()

    def _init_tree_sitter(self):
        try:
            from tree_sitter import Parser, Language  # type: ignore
            import importlib
            
            for lang_id in self.registry.list_languages():
                plugin = self.registry.get_plugin_by_id(lang_id)
                if plugin:
                    try:
                        # Dynamically load the modern standalone language module
                        mod_name = f"tree_sitter_{plugin.tree_sitter_lang_name}"
                        lang_module = importlib.import_module(mod_name)
                        
                        # Modern API: Language(lang_module.language())
                        if plugin.tree_sitter_lang_name == "typescript":
                            ts_lang = Language(lang_module.language_typescript())
                        else:
                            ts_lang = Language(lang_module.language())
                        parser = Parser(ts_lang)
                        self._parsers[lang_id] = parser
                    except Exception as e:
                        print(f"[TreeSitterParser] Failed to load {plugin.tree_sitter_lang_name}: {e}")
                        # Fallback or missing language build
                        pass
        except Exception as exc:
            print(f"[TreeSitterParser] Notice: tree_sitter initialized in lightweight / fallback mode: {exc}")

    def get_parser(self, lang_id: str) -> Optional[Any]:
        return self._parsers.get(lang_id)

    def parse(self, code_bytes: bytes, lang_id: str):
        """Returns a tree-sitter Tree object, or None if parser isn't available."""
        parser = self.get_parser(lang_id)
        if not parser:
            return None
        return parser.parse(code_bytes)
