from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List, Optional


DEFAULT_CONFIG: Dict[str, Any] = {
    "llm_provider": "ollama",
    "llm_model": "deepseek-coder:6.7b",
    "llm_endpoint": "http://localhost:11434/api/chat",
    "llm_temperature": 0.1,
    "llm_max_tokens": 1024,
    "llm_timeout_sec": 45,
    "embedding_model": "all-MiniLM-L6-v2",
    "qdrant_url": "http://localhost:6333",
    "qdrant_collection": "code_forensics_knowledge",
    "qdrant_timeout_sec": 30,
    "ignore_dirs": [
        ".git", "venv", ".env", "node_modules", "build", "dist",
        "__pycache__", ".idea", ".vscode", "qdrant_storage"
    ],
    "supported_extensions": [
        ".c", ".cpp", ".h", ".hpp", ".py", ".js", ".ts", ".java"
    ],
    "max_file_size_bytes": 1048576,
    "db_path": "database/forensics_ide.db",
    "log_level": "INFO",
    "ui_theme": "dark",
    "max_primevul_records": 500,
    "nvd_live_enabled": True,
}


class ConfigManager:
    """Thread-safe dynamic configuration manager for the Secure Code Forensics IDE."""

    _instance: Optional["ConfigManager"] = None
    _lock = threading.Lock()

    def __init__(self, config_path: Optional[str] = None):
        self.root_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_path = config_path or os.path.join(self.root_dir, "config.json")
        self._data: Dict[str, Any] = dict(DEFAULT_CONFIG)
        self._data_lock = threading.Lock()
        self.load()

    @classmethod
    def get_instance(cls, config_path: Optional[str] = None) -> "ConfigManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = ConfigManager(config_path)
        return cls._instance

    def load(self) -> Dict[str, Any]:
        with self._data_lock:
            if os.path.exists(self.config_path):
                try:
                    with open(self.config_path, "r", encoding="utf-8") as f:
                        loaded = json.load(f)
                        if isinstance(loaded, dict):
                            self._data.update(loaded)
                except Exception as exc:
                    print(f"[ConfigManager] Warning: Failed to load {self.config_path}: {exc}. Using defaults.")
            else:
                self._save_internal()
            return dict(self._data)

    def save(self) -> bool:
        with self._data_lock:
            return self._save_internal()

    def _save_internal(self) -> bool:
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True) if os.path.dirname(self.config_path) else None
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as exc:
            print(f"[ConfigManager] Error: Failed to save config to {self.config_path}: {exc}")
            return False

    def get(self, key: str, default: Any = None) -> Any:
        with self._data_lock:
            return self._data.get(key, default)

    def set(self, key: str, value: Any, auto_save: bool = True) -> None:
        with self._data_lock:
            self._data[key] = value
            if auto_save:
                self._save_internal()

    def update(self, updates: Dict[str, Any], auto_save: bool = True) -> None:
        with self._data_lock:
            self._data.update(updates)
            if auto_save:
                self._save_internal()

    def get_all(self) -> Dict[str, Any]:
        with self._data_lock:
            return dict(self._data)

    def is_ignored_dir(self, dir_name: str) -> bool:
        with self._data_lock:
            ignored = set(self._data.get("ignore_dirs", DEFAULT_CONFIG["ignore_dirs"]))
            return dir_name in ignored

    def is_supported_extension(self, ext: str) -> bool:
        with self._data_lock:
            supported = set(self._data.get("supported_extensions", DEFAULT_CONFIG["supported_extensions"]))
            return ext.lower() in supported
