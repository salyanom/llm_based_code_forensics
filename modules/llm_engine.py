from __future__ import annotations

from typing import Any, Dict, Generator, Optional
from config_manager import ConfigManager
from core.llm.client import LLMClient, LLMBackendOfflineError


class LLMEngine:
    """Legacy LLMEngine wrapper to maintain backward compatibility."""

    def __init__(self, prompt_builder: Optional[Any] = None):
        self.config = ConfigManager.get_instance()
        self.client = LLMClient()
        
        # Lazily load prompt builder to avoid circular imports if it gets extracted later
        if prompt_builder:
            self.prompt_builder = prompt_builder
        else:
            try:
                from modules.prompt_builder import PromptBuilderModule
                self.prompt_builder = PromptBuilderModule()
            except ImportError:
                self.prompt_builder = None

    def check_connection(self) -> Dict[str, Any]:
        """Check if the configured LLM backend is alive, model exists, and is callable."""
        return self.client.check_connection()

    def load_adapter(self, adapter_path: str) -> bool:
        """Dynamically load a LoRA adapter over the base DeepSeek-Coder weights."""
        return self.client.load_adapter(adapter_path)

    def execute_inference(
        self,
        prompt_data: Dict[str, Any],
        max_retries: int = 2,
    ) -> Dict[str, Any]:
        """Execute inference against the configured backend."""
        return self.client.execute_inference(prompt_data, max_retries)

    def stream_chat(
        self, prompt_data: Dict[str, Any]
    ) -> Generator[str, None, None]:
        """Stream chat tokens incrementally from the configured backend."""
        yield from self.client.stream_chat(prompt_data)
