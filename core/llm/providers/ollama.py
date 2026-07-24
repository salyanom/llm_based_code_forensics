import json
import time
import urllib.request
import urllib.error
from typing import Any, Dict, Generator

def infer(endpoint: str, model: str, prompt_data: Dict[str, Any], timeout: float, temp: float, max_tokens: int, retries: int, parse_func) -> Dict[str, Any]:
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
                return parse_func(msg_content, model)
        except Exception as exc:
            import traceback
            last_error = f"{exc.__class__.__name__}: {str(exc)}"
            print(f"[OllamaProvider] Attempt {attempt+1}/{retries+1} failed: {last_error}")
            time.sleep(0.5)

    raise Exception(f"Ollama backend at {endpoint} unreachable after {retries+1} attempts ({last_error}).")

def stream(endpoint: str, model: str, prompt_data: Dict[str, Any]) -> Generator[str, None, None]:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": prompt_data.get("system_prompt", "")},
            {"role": "user", "content": prompt_data.get("user_prompt", "")},
        ],
        "stream": True,
    }
    data_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(endpoint, data=data_bytes, headers={"Content-Type": "application/json"})
    
    with urllib.request.urlopen(req) as response:
        for line in response:
            if line:
                try:
                    chunk = json.loads(line.decode("utf-8"))
                    yield chunk.get("message", {}).get("content", "")
                    if chunk.get("done", False):
                        break
                except json.JSONDecodeError:
                    continue
