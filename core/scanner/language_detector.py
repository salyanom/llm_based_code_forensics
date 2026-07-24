import os
from typing import Optional, Tuple
from plugins import LanguagePlugin

class LanguageDetector:
    """
    Extracted from modules/parser.py.
    Responsible for identifying the programming language of a file based on its extension.
    """
    def __init__(self, registry):
        self.registry = registry

    def detect(self, file_path: str) -> Tuple[str, Optional[LanguagePlugin]]:
        """
        Detects the language of a file.
        Returns a tuple of (language_id, plugin_instance).
        """
        ext = os.path.splitext(file_path)[1].lower()
        plugin = self.registry.get_plugin_by_extension(ext)
        lang_id = plugin.language_id if plugin else "unknown"
        return lang_id, plugin
