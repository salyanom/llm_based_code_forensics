import json
import time
import urllib.request
from typing import Any, Dict, Generator

from config_manager import ConfigManager
from core.llm.providers import ollama, openai

class LLMBackendOfflineError(Exception):
    """Raised when the configured LLM backend is offline or unreachable."""
    pass

class LLMClient:
    """Stateless LLM client for API communication."""
    
    def __init__(self):
        self.config = ConfigManager.get_instance()
        self._hf_model = None
        self._hf_tokenizer = None

    def load_adapter(self, adapter_path: str) -> bool:
        import os
        if not os.path.exists(adapter_path):
            raise FileNotFoundError(f"Adapter directory not found: {adapter_path}")
        try:
            import torch  # type: ignore
            from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore
            from peft import PeftModel  # type: ignore

            base_model_id = self.config.get("llm_model", "deepseek-ai/deepseek-coder-1.3b-base")
            print(f"[LLMClient] Loading base model {base_model_id} and adapter {adapter_path}...")
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
            print(f"[LLMClient] Error loading LoRA adapter: {exc}")
            raise LLMBackendOfflineError(f"Could not load LoRA adapter {adapter_path}: {exc}")

    def check_connection(self) -> Dict[str, Any]:
        """Check if the configured LLM backend is alive, model exists, and is callable."""
        self.config.reload()
        provider = self.config.get("llm_provider", "ollama")
        endpoint = self.config.get("llm_endpoint", "http://localhost:11434/api/chat")
        model = self.config.get("llm_model", "deepseek-coder:6.7b")

        start_t = time.time()
        
        if provider == "ollama":
            try:
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

    def execute_inference(self, prompt_data: Dict[str, Any], max_retries: int = 2) -> Dict[str, Any]:
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

        print(f"[LLMClient.execute_inference] START provider={provider} model={model} prompt_len={prompt_len}")
        start_t = time.time()

        try:
            if provider == "ollama":
                res = ollama.infer(endpoint, model, prompt_data, timeout_sec, temperature, max_tokens, max_retries, self._parse_json_response)
            elif provider == "openai_compatible":
                res = openai.infer(endpoint, model, prompt_data, timeout_sec, temperature, max_tokens, max_retries, self._parse_json_response)
            elif provider == "huggingface_lora":
                if self._hf_model is None or self._hf_tokenizer is None:
                    raise LLMBackendOfflineError("HuggingFace/LoRA model not loaded in memory. Call load_adapter() first.")
                import torch  # type: ignore
                inputs = self._hf_tokenizer(prompt_data.get("full_prompt", ""), return_tensors="pt")
                if torch.cuda.is_available():
                    inputs = inputs.to("cuda")
                outputs = self._hf_model.generate(
                    **inputs, max_new_tokens=max_tokens, temperature=max(temperature, 0.01), do_sample=True
                )
                decoded = self._hf_tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
                res = self._parse_json_response(decoded, "HuggingFace-LoRA")
            else:
                raise LLMBackendOfflineError(f"Unsupported LLM provider: {provider}")

            duration = round(time.time() - start_t, 2)
            raw_resp = res.get("raw_text", json.dumps(res, ensure_ascii=False))
            print(f"[LLMClient.execute_inference] SUCCESS duration={duration}s resp_len={len(raw_resp)}")
            res["_inference_duration_sec"] = duration
            res["_prompt_len"] = prompt_len
            return res
        except Exception as exc:
            import traceback
            duration = round(time.time() - start_t, 2)
            err_msg = f"{exc.__class__.__name__}: {str(exc)}"
            tb_str = traceback.format_exc()
            print(f"[LLMClient.execute_inference] ERROR after {duration}s: {err_msg}\n{tb_str}")
            raise LLMBackendOfflineError(str(exc))

    def stream_chat(self, prompt_data: Dict[str, Any]) -> Generator[str, None, None]:
        provider = self.config.get("llm_provider", "ollama")
        endpoint = self.config.get("llm_endpoint", "http://localhost:11434/api/chat")
        model = self.config.get("llm_model", "deepseek-coder:6.7b")

        if provider == "ollama":
            yield from ollama.stream(endpoint, model, prompt_data)
        else:
            yield "Streaming not supported for this provider."

    def _parse_json_response(self, text: str, model_name: str) -> Dict[str, Any]:
        raw_text = text.strip()
        if not raw_text:
            return {"raw_text": "", "model": model_name, "error": "Empty response"}

        start = raw_text.find("{")
        end = raw_text.rfind("}")
        if start != -1 and end != -1 and end > start:
            json_str = raw_text[start : end + 1]
            try:
                data = json.loads(json_str)
                data["raw_text"] = raw_text
                data["model"] = model_name
                return data
            except json.JSONDecodeError:
                pass
                
        return {"raw_text": raw_text, "model": model_name, "parse_error": "Valid JSON not found"}
