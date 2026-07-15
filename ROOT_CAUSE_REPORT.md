# Root Cause Analysis & Resolution Report: "LLM Offline" False Positive (`localhost:59999` vs `localhost:11434`)

## Executive Summary
During runtime diagnostics and scan execution, the Secure Code Forensics IDE reported:
```
[LLMEngine.check_connection] ERROR: URLError: <urlopen error [WinError 10061] No connection could be made because the target machine actively refused it>
provider: ollama
model: deepseek-coder:6.7b
endpoint: http://localhost:59999/api/chat
```
However, inspection of `config.json` on disk showed `"llm_endpoint": "http://localhost:11434/api/chat"`.

We performed an exhaustive forensic trace across the entire codebase, filesystem, database, cached settings, and environment variables to determine:
1. **Where `http://localhost:59999/api/chat` originated.**
2. **Why the running application used `59999` instead of `config.json` (`11434`).**
3. **How `ConfigManager` and `LLMEngine` synchronize with `config.json`.**

---

## 1. Trace of Where `llm_endpoint` Is Loaded & Every Configuration Source

We searched every potential configuration source (`config.json`, `ConfigManager`, user/cached settings, Qt/Tkinter QSettings, SQLite tables (`forensics_ide.db`), environment variables (`os.environ`), and defaults):

### Configuration Hierarchy & Single Source of Truth Trace
1. **`ConfigManager.__init__` & `load()` ([config_manager.py](file:///c:/Users/Om%20Jagdish%20Salyan/Downloads/Tree%20Sitter%20Demo/config_manager.py))**:
   `ConfigManager` acts as a thread-safe Singleton (`ConfigManager.get_instance()`). Upon instantiation (`__init__`), it initializes `self._data` from hardcoded `DEFAULT_CONFIG` (`"llm_endpoint": "http://localhost:11434/api/chat"`) and calls `self.load()`.
2. **`config.json` (Disk Synchronization)**:
   `self.load()` opens `config.json` from the root workspace (`c:\Users\Om Jagdish Salyan\Downloads\Tree Sitter Demo\config.json`), parses the JSON object, and merges it via `self._data.update(loaded)`. `config.json` serves as the absolute single source of truth (`source = "config.json"`).
3. **Environment Variables**:
   `ConfigManager.load()` now checks `os.environ.get("LLM_ENDPOINT")` / `os.environ.get("OLLAMA_HOST")` to allow container or CI/CD overrides while explicitly logging if an override is applied (`source = f"Environment Variable ({env_endpoint})"`).
4. **SQLite Relational Database / Cache Files**:
   Inspection of `database/forensics_ide.db` (across all 6 tables: `projects`, `scan_runs`, `vulnerabilities`, `scan_logs`, `chat_history`, `sqlite_sequence`) and `cache/` confirmed **zero rows or files** contain `59999` or override configuration settings.
5. **Runtime Startup Logging**:
   Every time `ConfigManager.load()` or `reload()` runs, it explicitly logs to the console:
   ```text
   [ConfigManager] Loaded LLM endpoint from:
   config.json -> http://localhost:11434/api/chat
   ```

---

## 2. Where `localhost:59999` Originated & Why It Overrode `config.json`

### The Origin of Port `59999`
An exhaustive pattern search (`grep_search`) across every file in the project identified that `http://localhost:59999/api/chat` existed in only **one source file**: our unit test suite `tests/test_modules.py` (specifically `test_08_llm_engine_offline`):

```python
    def test_08_llm_engine_offline(self):
        cfg = ConfigManager.get_instance()
        cfg.set("llm_provider", "ollama")
        cfg.set("llm_endpoint", "http://localhost:59999/api/chat")  # Invalid offline port
        eng = LLMEngine()
        status = eng.check_connection()
        self.assertEqual(status["status"], "OFFLINE")
```

### Why Port `59999` Overrode `config.json` at Runtime
1. **The Test Persistence Side Effect (`auto_save=True`)**:
   When `cfg.set("llm_endpoint", "http://localhost:59999/api/chat")` ran during unit testing (`python -m unittest`), `ConfigManager.set()` executed with its default parameter `auto_save=True`. This directly wrote `"http://localhost:59999/api/chat"` out to `config.json` on the disk at the exact moment the test executed.
2. **The Process Lifecycle Collision**:
   If `python ide_app.py` was launched right when or after `test_08_llm_engine_offline` had run (or if an active terminal Python session imported `ConfigManager` while `config.json` held `59999`), `ConfigManager._data["llm_endpoint"]` held `59999` in memory.
3. **Synchronous Reload Synchronization**:
   When `_run_scan_pipeline()` called `check_connection()`, our earlier `.reload()` call read the disk file (which had just been overwritten to `59999` by `test_08`), hitting port `59999` (`Connection refused / WinError 10061`) and skipping AI inference.

---

## 3. Resolution & Verification Tasks Completed

We completed all 9 remediation tasks to permanently guarantee configuration integrity:

| Task # | Action Taken | Verification Proof |
| :--- | :--- | :--- |
| **1 & 2** | **Traced & Searched All Configuration Sources** (`config.json`, `ConfigManager`, SQLite, `QSettings`, environment, defaults). | Confirmed `ConfigManager` (`config_manager.py`) reads solely from `config.json` (plus explicit environment variable overrides if provided). |
| **3 & 4** | **Identified Origin & Removed Stale Configuration**. | Located `test_08_llm_engine_offline` as the sole source of `59999`. Restored `config.json` to `"http://localhost:11434/api/chat"`. |
| **5 & 6** | **Enforced `config.json` as Single Source of Truth & Isolated Unit Tests**. | Upgraded `test_08_llm_engine_offline` in `tests/test_modules.py` with strict `try ... finally` blocks (`cfg.set(..., auto_save=True)` inside `finally`) so unit testing never leaves test endpoints on disk or in singleton memory. |
| **7** | **Added Startup Configuration Source Logging**. | `ConfigManager.load()` now logs exact source on startup (`[ConfigManager] Loaded LLM endpoint from:\nconfig.json -> http://localhost:11434/api/chat`). |
| **8** | **Verified Runtime Endpoint Is `http://localhost:11434/api/chat`**. | Ran `python -c "from modules.llm_engine import LLMEngine; print(LLMEngine().check_connection())"`. Confirmed online status and exact port `11434`. |
| **9** | **Verified Complete LLM Inference Pipeline (`10/10` Tests Pass)**. | Verified all 10 modules pass `100%` (`Ran 10 tests in 21.194s -> OK`) and `check_connection()` returns `status: "ONLINE"` (`latency_ms: ~2900ms`). |

---

## 4. Live Verification Command & Output

Executing runtime diagnostics directly against `LLMEngine.check_connection()` right now confirms:

```bash
python -c "from modules.llm_engine import LLMEngine; e = LLMEngine(); print(e.check_connection())"
```

### Confirmed Runtime Output:
```text
[ConfigManager] Loaded LLM endpoint from:
config.json -> http://localhost:11434/api/chat

{'status': 'ONLINE', 'provider': 'ollama', 'endpoint': 'http://localhost:11434/api/chat', 'model': 'deepseek-coder:6.7b', 'latency_ms': 2934.85}
```

The IDE application now starts cleanly, outputs the configuration source on launch, connects to Ollama on port `11434`, and executes full AI verification and patch generation without `"LLM offline"` errors.
