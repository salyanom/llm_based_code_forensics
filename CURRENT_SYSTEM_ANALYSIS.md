# CURRENT SYSTEM ANALYSIS

> Generated: 2026-07-15 by automated pipeline verification against `code_samples/file1.c`

---

## 1. Complete Execution Flow

```
User clicks "Open Folder"
        │
        ▼
ide_app.py  ──► SecureCodeForensicsIDE.__init__()
                  │  Instantiates ALL modules on startup:
                  │    ConfigManager (Singleton, loads config.json)
                  │    ASTParserModule
                  │    PromptBuilderModule
                  │    LLMEngine(prompt_builder)
                  │    CorrelationModule  →  RAGRetrievalModule  →  EmbeddingsModule
                  │    VerificationModule
                  │    ExplainabilityModule
                  │    PatchGenerationModule(parser_module)
                  │    PersistenceModule (Singleton, SQLite)
                  │
        ▼
_open_project_folder()
        │  filedialog.askdirectory()
        │  PersistenceModule.register_or_get_project(folder) → project_id
        │  _populate_file_tree()  ← os.walk() filtered by ConfigManager ignore/extension lists
        │
        ▼
User clicks "Run Scan"
        │
        ▼
_start_scan_thread()
        │  threading.Thread(target=_run_scan_pipeline, daemon=True).start()
        │
        ▼
_run_scan_pipeline()  [background thread]
        │
        ├─► STEP 1: ASTParserModule.scan_project(folder)
        │     │  os.walk() → per-file: scan_file_incremental()
        │     │    Check incremental cache (SHA-256 + mtime)
        │     │    If changed → _parse_and_extract()
        │     │      tree_sitter Parser.parse() → traverse AST nodes
        │     │      OR heuristic regex fallback
        │     │    Extract: functions[], imports[], calls[], taint_candidates[]
        │     │    taint_candidates = {sink, sources_in_scope, line_number, is_sanitized}
        │     └─► Returns: {file_results{}, files_scanned, files_from_cache}
        │
        ├─► STEP 2: PersistenceModule.create_scan_run(project_id, files_count)
        │
        ├─► STEP 3: For each file → CorrelationModule.correlate_file_findings()
        │     │  For each taint_candidate:
        │     │    RAGRetrievalModule.retrieve_for_ast_candidate(candidate, lang)
        │     │      → EmbeddingsModule.encode_query(query_text)
        │     │      → np.dot(vectors, query_vec) cosine similarity
        │     │      → top-k matches with similarity_score
        │     │      → Extract cwe, cve, vulnerable_example, owasp_recommendation
        │     └─► Returns: correlated_items[]
        │
        ├─► STEP 4 (optional, LLM online only):
        │     LLMEngine.check_connection() → ONLINE/OFFLINE
        │     If ONLINE:
        │       PromptBuilderModule.build_verification_prompt(corr, rag_ctx, lang)
        │       LLMEngine.execute_inference(prompt) → {is_vulnerable, cwe, confidence, explanation, suggested_patch}
        │     If OFFLINE: llm_resp = {}
        │
        ├─► STEP 5: VerificationModule.verify_finding(corr, llm_resp)
        │     │  cwe from RAG (overridden by LLM if available)
        │     │  evaluate_cvss(cwe) → cvss_vector, cvss_score, severity
        │     │  calculate_confidence() → 0-100 int
        │     │    base=65, +10 not sanitized, +15 sources_in_scope>0
        │     │    +10 rag sim>0.5, +10 LLM confirms
        │     └─► Returns: verified_finding dict
        │
        ├─► STEP 6: PatchGenerationModule.generate_patch_for_finding(verified)
        │     │  If LLM provided suggested_patch → extract from ```code block
        │     │  Else heuristic regex replacements:
        │     │    strcpy → strncpy(buf, src, sizeof(buf)-1)
        │     │    sprintf → snprintf(buf, sizeof(buf), ...)
        │     │    gets → fgets(buf, sizeof(buf), stdin)
        │     │    system → neutralize with comment block
        │     │    eval / innerHTML → textContent
        │     │  difflib.unified_diff(original, patched) → unified_diff string
        │     │  validate_patch_ast() → check sink count reduction
        │     └─► Returns: {unified_diff, patched_snippet, is_valid, is_heuristic}
        │
        ├─► STEP 7: ExplainabilityModule.generate_evidence_explanation(verified)
        │     │  Compose: why_text, cwe_desc, cve_desc, primevul_example, owasp_rec, references
        │     └─► Returns: {why, supporting_cwe, supporting_cve, markdown_report, ...}
        │
        ├─► STEP 8: PersistenceModule.save_vulnerabilities(scan_id, all_findings)
        │     SQLite INSERT into vulnerabilities table (15 columns)
        │     update_scan_findings_count(scan_id, count)
        │
        └─► STEP 9: self.after(10, _on_scan_completed)
              _populate_file_tree()  ← updates badges (e.g., "● 3")
              _refresh_problems_table()
              _refresh_history_table()
              _switch_bottom_tab("problems")
```

---

## 2. Main Orchestrator / Controller

**`modules/ui_desktop.py` → class `SecureCodeForensicsIDE`** is the sole orchestrator.

- `ide_app.py` is a 30-line launcher that only imports and calls `app.mainloop()`.
- All module instantiation, pipeline coordination, threading, and UI update callbacks live in `ui_desktop.py`.
- There is **no separate controller class** — the UI class is the controller.

---

## 3. Module Interaction Map

```
ConfigManager (Singleton)
    │ config.json (llm_provider, embedding_model, ignore_dirs, etc.)
    ├── ASTParserModule
    │       └── PluginRegistry → [CPlugin, CppPlugin, PythonPlugin, JavaPlugin, JSPlugin, TSPlugin]
    │           Each plugin provides: taint_rules {sources, sinks, sanitizers, propagators}
    │           tree_sitter Parser (or heuristic fallback)
    │           Incremental cache: cache/incremental_ast_cache.json
    │
    ├── EmbeddingsModule (Singleton)
    │       sentence_transformers SentenceTransformer("all-MiniLM-L6-v2")
    │       OR hash-based 384-dim fallback
    │       Reads: data/merged_dataset.jsonl + data/taint_rules_dataset.json
    │       Writes: data/vector_index.npz + data/vector_metadata.json
    │
    ├── RAGRetrievalModule
    │       EmbeddingsModule.encode_query() → 384-dim vector
    │       np.dot(all_vectors, query_vec) → cosine similarity
    │       Returns: cwe, cve, owasp_recommendation, vulnerable_example, references
    │
    ├── CorrelationModule
    │       For each AST taint_candidate → RAGRetrievalModule.retrieve_for_ast_candidate()
    │       Bundles: file_path, function_name, sink, line_text, rag_context
    │
    ├── PromptBuilderModule
    │       build_verification_prompt() → system_prompt + user_prompt (token-budgeted)
    │       build_chat_prompt() → interactive AI chat
    │
    ├── LLMEngine
    │       check_connection() → TCP test to Ollama/OpenAI endpoint
    │       execute_inference() → Ollama /api/chat | OpenAI /v1/chat | HuggingFace LoRA
    │       stream_chat() → token-by-token generator for chat panel
    │       _parse_json_response() → extract {is_vulnerable, cwe, confidence, explanation, suggested_patch}
    │
    ├── VerificationModule
    │       CVSS_MAPPINGS: {CWE → (vector, score, severity)} for 8 CWEs
    │       calculate_confidence() → 0-100 int
    │       verify_finding() → adds cvss_vector, cvss_score, severity, confidence
    │
    ├── ExplainabilityModule
    │       generate_evidence_explanation() → structured dict + markdown_report string
    │
    ├── PatchGenerationModule
    │       generate_patch_for_finding() → heuristic regex or LLM suggested patch
    │       generate_unified_diff() → difflib.unified_diff
    │       validate_patch_ast() → sink count comparison
    │
    └── PersistenceModule (Singleton)
            SQLite: database/forensics_ide.db
            Tables: projects, scan_runs, vulnerabilities, scan_logs, chat_history
```

### Agents (UNUSED by UI pipeline)

The `agents/` directory contains 4 classes that import from `services/`:

| Agent | File | Dependencies | Status |
|---|---|---|---|
| `DetectionAgent` | `agents/detection_agent.py` | `services/parser_service.py` | **NOT used** by `ui_desktop.py` |
| `CorrelationAgent` | `agents/correlation_agent.py` | `services/rag_engine.py` | **NOT used** by `ui_desktop.py` |
| `VerificationAgent` | `agents/verification_agent.py` | `services/llm_service.py` | **NOT used** by `ui_desktop.py` |
| `PatchAgent` | `agents/patch_agent.py` | `services/llm_service.py`, `parser_service.py` | **NOT used** by `ui_desktop.py` |

The `agents/` layer is a **dead code path** — the UI directly calls `modules/` classes, bypassing all agents entirely.

---

## 4. Datasets Currently Used

| Dataset | Location | Format |
|---|---|---|
| Merged (PrimeVul+Juliet+OWASP+NVD) | `data/merged_dataset.jsonl` | JSONL (prompt/completion) |
| Taint Rules | `data/taint_rules_dataset.json` | JSON per language |
| RAG Export | `data/rag_export.jsonl` | JSONL (not indexed by default) |
| Dataset Candidates | `data/dataset_candidates.jsonl` | JSONL raw |
| Juliet (raw) | `knowledge/juliet.json` | JSON array |
| OWASP (raw) | `knowledge/owasp.json` | JSON array |
| NVD (raw) | `knowledge/nvd.json` | JSON array |
| NVD Live | `knowledge/nvd_live.json` | JSON (empty `[]`) |

---

## 5. Dataset Lifecycle Status

| Dataset | Raw | Preprocessed | Embedded in Vector DB | Used for RAG | Used for LoRA |
|---|:---:|:---:|:---:|:---:|:---:|
| PrimeVul | ❌ (not on disk) | ✅ (in merged_dataset.jsonl) | ✅ (via EmbeddingsModule) | ✅ | ❌ (no training done) |
| Juliet | ✅ (knowledge/juliet.json) | ✅ (partially in merged_dataset.jsonl) | ❌ (juliet.json NOT indexed) | ❌ | ❌ |
| OWASP | ✅ (knowledge/owasp.json) | ✅ (partially in merged_dataset.jsonl) | ❌ (owasp.json NOT indexed) | ❌ | ❌ |
| NVD | ✅ (knowledge/nvd.json) | ✅ (partially in merged_dataset.jsonl) | ❌ | ❌ | ❌ |
| Taint Rules | ✅ (data/taint_rules_dataset.json) | ✅ | ✅ (PRIMARY RAG source) | ✅ | ❌ |
| NVD Live | ✅ (knowledge/nvd_live.json) | ❌ (empty file `[]`) | ❌ | ❌ | ❌ |

**Critical finding**: The primary RAG vector index is built from `data/merged_dataset.jsonl` (small, 2.4KB, ~10 records) and `data/taint_rules_dataset.json` (7.4KB). The `knowledge/juliet.json`, `owasp.json`, `nvd.json` files are **NOT indexed** — `EmbeddingsModule.build_or_refresh_index()` only reads merged_dataset.jsonl and taint_rules_dataset.json.

---

## 6. Preprocessing Steps

### Module: `modules/dataset_preprocessing.py` → `DatasetPreprocessingModule`

**Step 1**: Load raw sources
- Reads `knowledge/juliet.json` → embedding_text field
- Reads `knowledge/owasp.json` → embedding_text field
- Reads `knowledge/nvd.json` → description field
- Downloads NVD live feed (if `nvd_live_enabled=True`)
- Can load HuggingFace `datasets` PrimeVul (optional)

**Step 2**: Normalize schemas
- Maps all records to `{prompt, completion, meta: {source, cwe, cve, title}}`

**Step 3**: SHA-256 deduplication
- `content_hash = sha256(prompt+completion)` → skip duplicates

**Step 4**: Export
- Writes `data/merged_dataset.jsonl` (prompt-completion pairs for LoRA training)

**Step 5**: Generate embeddings
- Calls `EmbeddingsModule.build_or_refresh_index(force_rebuild=True)`

**Gap**: This module exists but **is never called automatically**. It must be invoked manually. The `data/merged_dataset.jsonl` contains only ~10 records (2452 bytes), indicating preprocessing was run with a very small or empty dataset. The `knowledge/` JSON files are not automatically fed into the vector index at startup.

---

## 7. LLM Runtime Behaviour

### During Scan (offline mode — current state)
- `LLMEngine.check_connection()` returns `OFFLINE`
- `llm_resp = {}` (empty dict, no inference)
- Pipeline continues without LLM — uses purely AST + RAG

### During Scan (online mode)
- `PromptBuilderModule.build_verification_prompt()` constructs:
  - **System prompt**: "Output ONLY a valid JSON object with keys: is_vulnerable, vulnerability_type, cve, cvss_severity, confidence, explanation, attack_vector, suggested_patch"
  - **User prompt**: RAG threat intelligence block + AST function scope + taint candidates
- `LLMEngine.execute_inference()` → POST to Ollama `/api/chat` with `"format": "json"`
- Response parsed by `_parse_json_response()`:
  - Try `json.loads()` on response text
  - Fallback: if "vulnerable" or "cwe" in text → `is_vulnerable=True`

### Vulnerability Detection
The LLM does NOT do initial detection. Detection is done by **taint analysis** (parser + plugin rules). LLM performs **verification** only — it receives an already-detected candidate and confirms/enriches it.

### Verification
LLM response fields used: `is_vulnerable` → adjusts confidence ±10-30%, `vulnerability_type` → overrides CWE, `suggested_patch` → used by PatchGenerationModule.

### Explanation
LLM `explanation` field → used in `ExplainabilityModule.generate_evidence_explanation()` as the "why" text if present.

### Patch Generation
LLM `suggested_patch` field → if contains ``` code block, extracted and used as patched_snippet. Otherwise heuristic regex is used.

### Classification
CWE classification priority: LLM `vulnerability_type` > RAG `cwe` > "Unknown".

---

## 8. Agent Responsibilities

### `DetectionAgent` (agents/detection_agent.py)
- **Designed role**: Wraps `ParserService.extract_functions_from_folder()`
- **Actual status**: **DEAD CODE** — never instantiated or called by the UI pipeline
- **What it does**: Delegates to `services/parser_service.py` which is a separate (older) implementation

### `CorrelationAgent` (agents/correlation_agent.py)
- **Designed role**: Wraps `services/rag_engine.py` (NOT `modules/rag.py`) for correlation queries
- **Actual status**: **DEAD CODE** — never used by UI pipeline
- **Note**: Uses `services/rag_engine.py` (Qdrant-based) vs production `modules/rag.py` (NumPy cosine)

### `VerificationAgent` (agents/verification_agent.py)
- **Designed role**: Full CVSS calculation with optional `cvss` library, LLM-backed verification, rule-based findings, evidence filtering, deduplication
- **Actual status**: **DEAD CODE** — never used by UI pipeline
- **Note**: More sophisticated than `modules/verification.py` — includes `_evidence_filter()`, `_is_evidence_consistent()`, `_floor_severity()`, full CVSS metric normalization

### `PatchAgent` (agents/patch_agent.py)
- **Designed role**: LLM-backed patch generation + multi-check patch validation
- **Actual status**: **DEAD CODE** — never used by UI pipeline
- **Note**: `verify_patch()` method has richer validation (5 check types) than `modules/patch_generation.validate_patch_ast()`

---

## 9. Architecture Type

**Sequential Pipeline with Opportunistic LLM Skip**

The system is a **sequential, synchronous pipeline** (run in a background thread):

```
AST Parse → Correlate → [LLM Verify]? → CVSS/Confidence → Patch → Explain → Persist
```

It is NOT an orchestrated multi-agent workflow. The agents in `agents/` and `services/` represent a **prior architectural design** that was never connected to the current UI. The current production code path uses modules directly.

There is no:
- Message bus or event queue
- Agent supervisor or orchestrator
- Retry/fallback between agents
- Parallel agent execution

---

## 10. Missing or Incomplete Modules

| Issue | Detail |
|---|---|
| **Agents disconnected** | All 4 agents in `agents/` are dead code — not wired to the UI pipeline |
| **services/ disconnected** | `services/parser_service.py`, `services/rag_engine.py`, `services/llm_service.py` are never used by the UI |
| **knowledge/ not indexed** | `juliet.json`, `owasp.json`, `nvd.json` not read by `EmbeddingsModule` |
| **merged_dataset.jsonl tiny** | Only ~10 records (2.4KB); preprocessing was run on empty/minimal data |
| **No progress feedback** | Scan runs silently — no per-stage status updates to UI during scan |
| **Parser over-detects** | `printf` is treated as a function definition AND a sink, creating false positives |
| **sources_in_scope always empty** | Taint source tracking is per-function-scope but doesn't track cross-function data flow; `gets(user_input)` → `system(command)` cross-function path is not linked |
| **Confidence formula simplistic** | Base 65% regardless of finding quality; `sources_in_scope` is always `[]` in practice |
| **RAG misses juliet/owasp/nvd** | Only `taint_rules_dataset.json` + tiny `merged_dataset.jsonl` indexed |
| **LLM forced JSON format** | Ollama `"format": "json"` may fail if model doesn't support it |
| **Evidence panel empty in UI** | `explanation_json.markdown_report` is generated but not rendered with proper formatting |
| **Patch panel empty in UI** | `patch_diff` is generated but the diff viewer was not coloring lines correctly |
| **History isolated** | `get_scan_vulnerabilities()` reloads from DB but `correlated_item` (RAG context) is not persisted — so history records show no evidence |
