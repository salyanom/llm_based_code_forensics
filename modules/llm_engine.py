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
        """Check if the configured LLM backend is alive, model exists, and is callable."""
        self.config.reload()
        provider = self.config.get("llm_provider", "ollama")
        endpoint = self.config.get("llm_endpoint", "http://localhost:11434/api/chat")
        model = self.config.get("llm_model", "deepseek-coder:6.7b")

        start_t = time.time()
        if provider == "ollama":
            try:
                # 1. Try using the Ollama Python library if available
                try:
                    import ollama
                    models_data = ollama.list()
                    model_names = []
                    if isinstance(models_data, dict):
                        for m in models_data.get("models", []):
                            if isinstance(m, dict):
                                model_names.append(m.get("model", "") or m.get("name", ""))
                            else:
                                model_names.append(getattr(m, "model", "") or getattr(m, "name", ""))
                    elif hasattr(models_data, "models"):
                        for m in models_data.models:
                            model_names.append(getattr(m, "model", "") or getattr(m, "name", ""))
                    elif isinstance(models_data, list):
                        for m in models_data:
                            model_names.append(getattr(m, "model", "") if not isinstance(m, dict) else (m.get("model", "") or m.get("name", "")))
                    
                    if model_names and not any(model.split(":")[0] in name.split(":")[0] for name in model_names if name):
                        return {
                            "status": "OFFLINE",
                            "error": f"Model '{model}' not installed on Ollama server. Available: {', '.join(model_names)}",
                            "exception": "ModelNotFoundError",
                            "provider": provider,
                            "endpoint": endpoint,
                            "model": model,
                        }
                except Exception:
                    pass

                # 2. HTTP Probing of Ollama server (/api/tags or root)
                base_url = endpoint.split("/api")[0] if "/api" in endpoint else endpoint.rsplit("/", 1)[0]
                tags_url = f"{base_url}/api/tags"
                req = urllib.request.Request(tags_url, method="GET")
                with urllib.request.urlopen(req, timeout=4.0) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        installed = [m.get("name", "") or m.get("model", "") for m in data.get("models", [])]
                        if installed and not any(model.split(":")[0] in name.split(":")[0] for name in installed if name):
                            return {
                                "status": "OFFLINE",
                                "error": f"Model '{model}' not installed on server. Available models: {', '.join(installed)}",
                                "exception": "ModelNotFoundError",
                                "provider": provider,
                                "endpoint": endpoint,
                                "model": model,
                            }
                latency_ms = round((time.time() - start_t) * 1000, 2)
                return {
                    "status": "ONLINE",
                    "provider": provider,
                    "endpoint": endpoint,
                    "model": model,
                    "latency_ms": latency_ms,
                }
            except Exception as exc:
                import traceback
                err_msg = f"{exc.__class__.__name__}: {str(exc)}"
                print(f"[LLMEngine.check_connection] ERROR: {err_msg}\n{traceback.format_exc()}")
                return {
                    "status": "OFFLINE",
                    "error": str(exc),
                    "exception": exc.__class__.__name__,
                    "provider": provider,
                    "endpoint": endpoint,
                    "model": model,
                }

        elif provider == "openai_compatible":
            try:
                test_url = endpoint.split("/v1")[0] + "/v1/models" if "/v1" in endpoint else endpoint
                req = urllib.request.Request(test_url, method="GET")
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    latency_ms = round((time.time() - start_t) * 1000, 2)
                    return {"status": "ONLINE", "provider": provider, "endpoint": endpoint, "model": model, "latency_ms": latency_ms}
            except Exception as exc:
                return {"status": "OFFLINE", "provider": provider, "endpoint": endpoint, "error": str(exc), "exception": exc.__class__.__name__, "model": model}

        elif provider == "huggingface_lora":
            if self._hf_model is not None:
                return {"status": "ONLINE", "provider": provider, "model": model, "latency_ms": 0.0}
            return {"status": "OFFLINE", "provider": provider, "error": "HuggingFace/LoRA model not loaded in memory", "exception": "ModelNotLoadedError", "model": model}

        return {"status": "UNKNOWN", "provider": provider, "model": model}

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
        self.config.reload()
        provider = self.config.get("llm_provider", "ollama")
        timeout_sec = float(self.config.get("llm_timeout_sec", 45))
        temperature = float(self.config.get("llm_temperature", 0.1))
        max_tokens = int(self.config.get("llm_max_tokens", 1024))

        sys_p = prompt_data.get("system_prompt", "")
        usr_p = prompt_data.get("user_prompt", "")
        prompt_len = len(sys_p) + len(usr_p)
        model = self.config.get("llm_model", "deepseek-coder:6.7b")
        endpoint = self.config.get("llm_endpoint", "http://localhost:11434/api/chat")

        print(f"[LLMEngine.execute_inference] START provider={provider} model={model} prompt_len={prompt_len}")
        start_t = time.time()

        try:
            if provider == "ollama":
                res = self._infer_ollama(prompt_data, timeout_sec, temperature, max_tokens, max_retries)
            elif provider == "openai_compatible":
                res = self._infer_openai(prompt_data, timeout_sec, temperature, max_tokens, max_retries)
            elif provider == "huggingface_lora":
                res = self._infer_huggingface(prompt_data, temperature, max_tokens)
            else:
                raise LLMBackendOfflineError(f"Unsupported LLM provider: {provider}")

            duration = round(time.time() - start_t, 2)
            raw_resp = res.get("raw_text", json.dumps(res, ensure_ascii=False))
            print(f"[LLMEngine.execute_inference] SUCCESS duration={duration}s resp_len={len(raw_resp)}")
            res["_inference_duration_sec"] = duration
            res["_prompt_len"] = prompt_len
            return res
        except Exception as exc:
            import traceback
            duration = round(time.time() - start_t, 2)
            err_msg = f"{exc.__class__.__name__}: {str(exc)}"
            tb_str = traceback.format_exc()
            print(f"[LLMEngine.execute_inference] ERROR after {duration}s: {err_msg}\n{tb_str}")
            raise

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
            except Exception as exc:
                import traceback
                last_error = f"{exc.__class__.__name__}: {str(exc)}"
                print(f"[LLMEngine._infer_ollama] Attempt {attempt+1}/{retries+1} failed: {last_error}")
                if attempt == retries:
                    print(traceback.format_exc())
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
            if isinstance(parsed, list):
                if len(parsed) > 0 and isinstance(parsed[0], dict):
                    obj = dict(parsed[0])
                    obj["_model_used"] = model_used
                    obj["_raw_array"] = parsed
                    obj["raw_text"] = text
                    return obj
                elif len(parsed) == 0:
                    return {
                        "is_vulnerable": False,
                        "vulnerability_type": "None",
                        "explanation": "LLM returned empty JSON array [] indicating no vulnerabilities.",
                        "raw_text": text,
                        "_model_used": model_used,
                    }
            if isinstance(parsed, dict):
                parsed["_model_used"] = model_used
                parsed["raw_text"] = text
                return parsed
        except Exception:
            # Try finding first '[' or '{' if extra leading/trailing text exists
            try:
                first_bracket = text_clean.find("[")
                last_bracket = text_clean.rfind("]")
                first_brace = text_clean.find("{")
                last_brace = text_clean.rfind("}")

                if first_bracket != -1 and last_bracket != -1 and last_bracket > first_bracket and (first_brace == -1 or first_bracket < first_brace):
                    sub = text_clean[first_bracket:last_bracket + 1]
                    arr = json.loads(sub)
                    if isinstance(arr, list) and len(arr) > 0 and isinstance(arr[0], dict):
                        obj = dict(arr[0])
                        obj["_model_used"] = model_used
                        obj["raw_text"] = text
                        return obj
                if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                    sub = text_clean[first_brace:last_brace + 1]
                    obj = json.loads(sub)
                    if isinstance(obj, dict):
                        obj["_model_used"] = model_used
                        obj["raw_text"] = text
                        return obj
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
