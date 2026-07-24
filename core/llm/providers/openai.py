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
                return parse_func(content, model)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
            print(f"[OpenAIProvider] Attempt {attempt+1}/{retries+1} failed: {last_error}")
            time.sleep(0.5)

    raise Exception(f"OpenAI-compatible backend at {endpoint} unreachable after {retries+1} attempts ({last_error}).")
