from __future__ import annotations

import json
import os
import time
import urllib.request
import urllib.error
from typing import Any, Dict, Generator, List, Optional

from config_manager import ConfigManager
from modules.prompt_builder import PromptBuilderModule


class LLMBackendOfflineError(Exception):
    """Raised when the configured LLM backend is offline or unreachable."""
    pass


class LLMEngine:
    """Unified LLM Engine responsible for model loading, inference, adapters, and streaming."""

    def __init__(self, prompt_builder: Optional[PromptBuilderModule] = None):
        self.config = ConfigManager.get_instance()
        self.prompt_builder = prompt_builder or PromptBuilderModule()
        self._hf_model = None
        self._hf_tokenizer = None

    def check_connection(self) -> Dict[str, Any]:
        """Check if the configured LLM backend is alive and accessible."""
        provider = self.config.get("llm_provider", "ollama")
        endpoint = self.config.get("llm_endpoint", "http://localhost:11434/api/chat")
        model = self.config.get("llm_model", "deepseek-coder:6.7b")

        if provider in {"ollama", "openai_compatible"}:
            try:
                # Test reachability of host/port
                test_url = endpoint.split("/api")[0] if "/api" in endpoint else endpoint.split("/v1")[0]
                req = urllib.request.Request(test_url, method="GET")
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    if resp.status in {200, 404}:
                        return {"status": "ONLINE", "provider": provider, "endpoint": endpoint, "model": model}
            except Exception as exc:
                return {"status": "OFFLINE", "provider": provider, "endpoint": endpoint, "error": str(exc)}

        elif provider == "huggingface_lora":
            if self._hf_model is not None:
                return {"status": "ONLINE", "provider": provider, "model": model}
            return {"status": "OFFLINE", "provider": provider, "error": "HuggingFace/LoRA model not loaded in memory"}

        return {"status": "UNKNOWN", "provider": provider}

    def load_adapter(self, adapter_path: str) -> bool:
        """Dynamically load a LoRA adapter over the base DeepSeek-Coder weights."""
        if not os.path.exists(adapter_path):
            raise FileNotFoundError(f"Adapter directory not found: {adapter_path}")
        try:
            import torch  # type: ignore
            from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore
            from peft import PeftModel  # type: ignore

            base_model_id = self.config.get("llm_model", "deepseek-ai/deepseek-coder-1.3b-base")
            print(f"[LLMEngine] Loading base model {base_model_id} and adapter {adapter_path}...")
            tokenizer = AutoTokenizer.from_pretrained(base_model_id, trust_remote_code=True)
            model = AutoModelForCausalLM.from_pretrained(
                base_model_id, trust_remote_code=True, device_map="auto" if torch.cuda.is_available() else "cpu"
            )
            model = PeftModel.from_pretrained(model, adapter_path)
            self._hf_model = model
            self._hf_tokenizer = tokenizer
            self.config.set("llm_provider", "huggingface_lora")
            return True
        except Exception as exc:
            print(f"[LLMEngine] Error loading LoRA adapter: {exc}")
            raise LLMBackendOfflineError(f"Could not load LoRA adapter {adapter_path}: {exc}")

    def execute_inference(
        self,
        prompt_data: Dict[str, Any],
        max_retries: int = 2,
    ) -> Dict[str, Any]:
        """Execute inference against the configured backend. Raises LLMBackendOfflineError if unreachable after retries."""
        provider = self.config.get("llm_provider", "ollama")
        timeout_sec = float(self.config.get("llm_timeout_sec", 45))
        temperature = float(self.config.get("llm_temperature", 0.1))
        max_tokens = int(self.config.get("llm_max_tokens", 1024))

        if provider == "ollama":
            return self._infer_ollama(prompt_data, timeout_sec, temperature, max_tokens, max_retries)
        elif provider == "openai_compatible":
            return self._infer_openai(prompt_data, timeout_sec, temperature, max_tokens, max_retries)
        elif provider == "huggingface_lora":
            return self._infer_huggingface(prompt_data, temperature, max_tokens)
        else:
            raise LLMBackendOfflineError(f"Unsupported LLM provider: {provider}")

    def _infer_ollama(
        self, prompt_data: Dict[str, Any], timeout: float, temp: float, max_tokens: int, retries: int
    ) -> Dict[str, Any]:
        endpoint = self.config.get("llm_endpoint", "http://localhost:11434/api/chat")
        model = self.config.get("llm_model", "deepseek-coder:6.7b")

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": prompt_data.get("system_prompt", "")},
                {"role": "user", "content": prompt_data.get("user_prompt", "")},
            ],
            "stream": False,
            "format": "json",
            "options": {"temperature": temp, "num_predict": max_tokens},
        }

        data_bytes = json.dumps(payload).encode("utf-8")
        last_error = ""

        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(endpoint, data=data_bytes, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    resp_json = json.loads(resp.read().decode("utf-8"))
                    msg_content = resp_json.get("message", {}).get("content", "")
                    return self._parse_json_response(msg_content, model)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = str(exc)
                time.sleep(0.5)

        raise LLMBackendOfflineError(
            f"Ollama LLM Backend at {endpoint} unreachable after {retries+1} attempts ({last_error}). "
            f"Please verify Ollama is running and model '{model}' is pulled, or switch models in Settings."
        )

    def _infer_openai(
        self, prompt_data: Dict[str, Any], timeout: float, temp: float, max_tokens: int, retries: int
    ) -> Dict[str, Any]:
        endpoint = self.config.get("llm_endpoint", "http://localhost:8000/v1/chat/completions")
        model = self.config.get("llm_model", "deepseek-coder")

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": prompt_data.get("system_prompt", "")},
                {"role": "user", "content": prompt_data.get("user_prompt", "")},
            ],
            "temperature": temp,
            "max_tokens": max_tokens,
        }

        data_bytes = json.dumps(payload).encode("utf-8")
        last_error = ""

        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(endpoint, data=data_bytes, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    resp_json = json.loads(resp.read().decode("utf-8"))
                    choices = resp_json.get("choices", [])
                    content = choices[0].get("message", {}).get("content", "") if choices else ""
                    return self._parse_json_response(content, model)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = str(exc)
                time.sleep(0.5)

        raise LLMBackendOfflineError(
            f"OpenAI-compatible server at {endpoint} unreachable after {retries+1} attempts ({last_error})."
        )

    def _infer_huggingface(self, prompt_data: Dict[str, Any], temp: float, max_tokens: int) -> Dict[str, Any]:
        if self._hf_model is None or self._hf_tokenizer is None:
            raise LLMBackendOfflineError("HuggingFace/LoRA model not loaded in memory. Call load_adapter() first.")
        try:
            import torch  # type: ignore
            inputs = self._hf_tokenizer(prompt_data.get("full_prompt", ""), return_tensors="pt")
            if torch.cuda.is_available():
                inputs = inputs.to("cuda")
            outputs = self._hf_model.generate(
                **inputs, max_new_tokens=max_tokens, temperature=max(temp, 0.01), do_sample=True
            )
            decoded = self._hf_tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
            return self._parse_json_response(decoded, "HuggingFace-LoRA")
        except Exception as exc:
            raise LLMBackendOfflineError(f"HuggingFace inference error: {exc}")

    def stream_chat(
        self, prompt_data: Dict[str, Any]
    ) -> Generator[str, None, None]:
        """Stream chat tokens incrementally from the configured backend."""
        provider = self.config.get("llm_provider", "ollama")
        endpoint = self.config.get("llm_endpoint", "http://localhost:11434/api/chat")
        model = self.config.get("llm_model", "deepseek-coder:6.7b")

        if provider == "ollama":
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": prompt_data.get("system_prompt", "")},
                    {"role": "user", "content": prompt_data.get("user_prompt", "")},
                ],
                "stream": True,
            }
            data_bytes = json.dumps(payload).encode("utf-8")
            try:
                req = urllib.request.Request(endpoint, data=data_bytes, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=15.0) as resp:
                    for line in resp:
                        if not line.strip():
                            continue
                        try:
                            chunk = json.loads(line.decode("utf-8"))
                            token = chunk.get("message", {}).get("content", "")
                            if token:
                                yield token
                        except Exception:
                            continue
            except Exception as exc:
                raise LLMBackendOfflineError(f"Ollama streaming failed: {exc}")
        else:
            # Non-streaming fallback wrapped as generator
            res = self.execute_inference(prompt_data)
            yield res.get("raw_text", json.dumps(res))

    @staticmethod
    def _parse_json_response(text: str, model_used: str) -> Dict[str, Any]:
        text_clean = text.strip()
        if "```json" in text_clean:
            parts = text_clean.split("```json")
            if len(parts) > 1:
                text_clean = parts[1].split("```")[0].strip()
        elif "```" in text_clean:
            parts = text_clean.split("```")
            if len(parts) > 1:
                text_clean = parts[1].strip()

        try:
            parsed = json.loads(text_clean)
            if isinstance(parsed, dict):
                parsed["_model_used"] = model_used
                return parsed
        except Exception:
            pass

        # Return raw text structure if not strict json
        return {
            "is_vulnerable": "vulnerable" in text.lower() or "cwe" in text.lower(),
            "vulnerability_type": "Check Explanation",
            "explanation": text,
            "raw_text": text,
            "_model_used": model_used,
        }
