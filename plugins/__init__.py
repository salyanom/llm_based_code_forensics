from __future__ import annotations

import importlib
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set


class LanguagePlugin(ABC):
    """Abstract base class for all language plugins in the Code Forensics IDE."""

    @property
    @abstractmethod
    def language_id(self) -> str:
        """Unique identifier for the language (e.g., 'c', 'python', 'java')."""
        pass

    @property
    @abstractmethod
    def extensions(self) -> Set[str]:
        """File extensions associated with this language (e.g., {'.c', '.h'})."""
        pass

    @property
    @abstractmethod
    def tree_sitter_lang_name(self) -> str:
        """Name used by tree_sitter_languages.get_language() (e.g., 'c', 'python', 'java', 'javascript', 'typescript', 'cpp')."""
        pass

    @abstractmethod
    def get_taint_signatures(self) -> Dict[str, Set[str]]:
        """Return dict with 'sources', 'sinks', 'propagators', 'sanitizers' sets."""
        pass

    @abstractmethod
    def is_function_node(self, node: Any) -> bool:
        """Check if AST node represents a function or method definition."""
        pass

    @abstractmethod
    def extract_function_name(self, node: Any, code_bytes: bytes) -> str:
        """Extract function name from a function AST node."""
        pass


class PluginRegistry:
    """Registry managing all available language plugins."""

    def __init__(self):
        self._plugins: Dict[str, LanguagePlugin] = {}
        self._ext_map: Dict[str, str] = {}
        self._discover_plugins()

    def _discover_plugins(self):
        plugins_dir = os.path.dirname(os.path.abspath(__file__))
        for file_name in sorted(os.listdir(plugins_dir)):
            if file_name.endswith(".py") and not file_name.startswith("_"):
                mod_name = file_name[:-3]
                try:
                    module = importlib.import_module(f"plugins.{mod_name}")
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (
                            isinstance(attr, type)
                            and issubclass(attr, LanguagePlugin)
                            and attr is not LanguagePlugin
                        ):
                            plugin = attr()
                            self.register(plugin)
                except Exception as exc:
                    print(f"[PluginRegistry] Warning: Could not load plugin {mod_name}: {exc}")

    def register(self, plugin: LanguagePlugin):
        self._plugins[plugin.language_id] = plugin
        for ext in plugin.extensions:
            self._ext_map[ext.lower()] = plugin.language_id

    def get_plugin_by_id(self, language_id: str) -> Optional[LanguagePlugin]:
        return self._plugins.get(language_id.lower())

    def get_plugin_by_extension(self, ext: str) -> Optional[LanguagePlugin]:
        lang_id = self._ext_map.get(ext.lower())
        if lang_id:
            return self._plugins.get(lang_id)
        return None

    def list_languages(self) -> List[str]:
        return sorted(self._plugins.keys())

    def list_supported_extensions(self) -> List[str]:
        return sorted(self._ext_map.keys())


# Singleton registry instance
_registry: Optional[PluginRegistry] = None


def get_plugin_registry() -> PluginRegistry:
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
    return _registry
