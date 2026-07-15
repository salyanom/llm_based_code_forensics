# 🛡️ Secure Code Forensics IDE — Modular AI-Powered Vulnerability Analysis Platform

An enterprise-grade, **modular desktop IDE application** designed for deep security code forensics. Unlike traditional single-file scanners, this platform opens entire project folders recursively, extracts multi-language Abstract Syntax Trees (AST) via **Tree-sitter**, correlates detected taint flows (`sources` → `sinks`) with **Retrieval-Augmented Generation (RAG)** threat intelligence (`PrimeVul`, `Juliet`, `OWASP`, `NVD`), verifies findings using a **LoRA-adapted DeepSeek-Coder model**, calculates **CVSS 3.1** vectors and **Confidence Scores (0–100%)**, and generates git-compatible **Unified Diff Patches** (`--- a/ +++ b/`) that can be applied directly to disk files.

---

## 🏛️ System Architecture (`10/10` Modular Design)

The system is architected into 10 independent, decoupled modules with clean APIs so each component can be developed, tested, and scaled without unintended side effects:

| # | Module Name | File Path | Core Responsibilities & Capabilities |
|---|---|---|---|
| **1** | **Configuration Manager** | `config_manager.py` | Dynamic `config.json` management via thread-safe Singleton (`ConfigManager.get_instance()`). Handles `.gitignore` and directory exclusion (`.git`, `venv`, `node_modules`, `build`, `dist`), supported extension validation, and runtime threshold storage. |
| **2** | **Plugin & Language Registry** | `plugins/` | Abstract `LanguagePlugin` interface with concrete implementations for **C** (`c_plugin.py`), **C++** (`cpp_plugin.py`), **Python** (`python_plugin.py`), **Java** (`java_plugin.py`), **JavaScript** (`javascript_plugin.py`), and **TypeScript** (`typescript_plugin.py`). Extracts per-language taint rules (`sources`, `sinks`, `propagators`, `sanitizers`). |
| **3** | **Dataset Preprocessing** | `modules/dataset_preprocessing.py` | Dedicated pipeline normalizing `Juliet`, `OWASP`, and `NVD` feeds. Deduplicates samples by SHA-256 (`content_hash`), cleans invalid records, maps canonical `CWE`/`CVE` codes, and exports standardized prompt-completion JSONL (`data/merged_dataset.jsonl`). |
| **4** | **Fine-Tuning Pipeline** | `modules/fine_tuning.py` | `peft` / `LoRA` adapter training pipeline (`r=16`, `lora_alpha=32`, target attention modules `q_proj`, `v_proj`, `k_proj`, `o_proj`) for `DeepSeek-Coder`. Saves adapter weights (`checkpoints/lora_adapter/adapter_config.json`). |
| **5** | **AST Parser & Incremental Engine** | `modules/parser.py` | Multi-language Tree-sitter AST extraction (`functions`, `classes`, `imports`, `call graphs`, and `taint candidates`). Features a sub-100ms **Incremental Scanning Engine** (`cache/incremental_ast_cache.json`) checking file `mtime` and SHA-256 hashes to re-analyze only changed files. |
| **6** | **Embeddings Pipeline** | `modules/embeddings.py` | `SentenceTransformer` vectorization (`all-MiniLM-L6-v2`) with automatic lightweight TF-IDF/Hash fallback. Indexes all security samples and rules into vector matrices (`data/vector_index.npz`). |
| **7** | **RAG Retrieval Engine** | `modules/rag.py` | Semantic vector search performing cosine similarity ranking (`np.dot`) over indexed security knowledge. Retrieves exact matching `CWE`, `CVE`, vulnerable dataset examples, OWASP remediation guidelines, and references for any AST finding. |
| **8** | **Dynamic Prompt Builder** | `modules/prompt_builder.py` | Dynamic prompt construction and token budgeting (`max_input_tokens = 3500`). Dynamically allocates token budget across system instructions, RAG threat intelligence, and code context without overflowing LLM context limits. |
| **9** | **LLM Engine & Offline Guard** | `modules/llm_engine.py` | Unified inference engine supporting `Ollama`, `OpenAI-compatible` servers, and local LoRA adapters (`PeftModel`). **Strict Offline Rule Enforced**: If the backend is offline or unreachable after retries, it raises an explicit `LLMBackendOfflineError` (**no mock or simulated security findings**). |
| **10** | **Correlation, Verification & Explainability** | `modules/correlation.py`<br>`modules/verification.py`<br>`modules/explainability.py` | Correlates AST taint flow candidates with RAG intelligence. Normalizes `CVSS 3.1` metric vectors (`AV:N/AC:L/PR:N/...`), maps canonical CWE/CVE, and computes a strict **Confidence Score (`0-100%`)**. Formats evidence breakdowns: `Why` → `Supporting CWE` → `Supporting CVE` → `PrimeVul Example` → `OWASP Remediation` → `References`. |
| **11** | **Unified Diff Patch Generation** | `modules/patch_generation.py` | Generates git-compatible unified code diffs (`--- a/path +++ b/path`). Validates patch safety via AST re-parsing (`validate_patch_ast()`) verifying that unbounded sinks (`strcpy`, `sprintf`, `gets`) are reduced or replaced by bounded APIs (`strncpy`, `snprintf`, `fgets`). |
| **12** | **Persistence & Searchable History** | `modules/persistence.py` | Thread-safe SQLite relational database (`database/forensics_ide.db`) managing `projects`, `scan_runs`, `vulnerabilities`, `scan_logs`, and `chat_history`. Enables fast history queries and instant reload of historical scan findings. |
| **13** | **Rich IDE Desktop Application** | `modules/ui_desktop.py`<br>`ide_app.py` | Modern multi-paned Tkinter/TTK Desktop Window featuring Project Explorer tree (with issue badges), Source Code Editor (with line numbers and vulnerable line highlighting), Problems Table, Evidence Explainability Panel, Unified Diff Patch Preview (`Apply Patch to Disk File`), Interactive AI Chat Panel, Scan Diagnostics Console, Searchable History Table, and Settings Dialog. |

---

## 🚀 Installation & Prerequisites

### 1. Requirements
- **OS**: Windows, macOS, or Linux
- **Python**: 3.9, 3.10, or 3.11+
- **Optional**: [Ollama](https://ollama.ai/) installed locally running `deepseek-coder:6.7b` (or `codellama`, `llama3`) on `http://localhost:11434/api/chat` if you wish to use live LLM verification and chat.

### 2. Setup Environment
Open your terminal in the repository root directory and install dependencies:

```powershell
# Create and activate virtual environment (Recommended)
python -m venv venv
.\venv\Scripts\activate

# Install required Python packages
pip install -r requirements.txt
```

---

## 🎯 How to Run the IDE Application

### 1. Launch the Desktop IDE Shell
To start the modular graphical application, run the main entry point:

```powershell
python ide_app.py
```

### 2. Using the IDE
1. **Open a Project Folder**:
   - Click **`📁 Open Project Folder`** in the top toolbar and choose any directory containing source code (such as `code_samples` or your own project).
   - The **Project Explorer** tree on the left will recursively display all supported source files (`.c`, `.cpp`, `.py`, `.java`, `.js`, `.ts`) while ignoring `.git`, `venv`, `node_modules`, `build`, and `dist`.

2. **Run a Multi-Language Security Scan**:
   - Ensure **`⚡ Incremental Mode [Sub-100ms Cache]`** is checked if you want ultra-fast re-scans.
   - Click **`🚀 Run Security Scan`**.
   - The scan runs asynchronously in a background thread without freezing the UI. Real-time progress is streamed directly to the **Status Bar** and **Diagnostics Console**.
   - Once completed, files with confirmed issues display visual badges (e.g., `🔴 2`) in the tree, and the **🚨 Problems Table** populates with confirmed findings sorted by severity (`Critical`, `High`, `Medium`, `Low`) and confidence.

3. **Inspect Evidence & Explainability**:
   - Click any row in the **🚨 Problems Table**.
   - The **Source Editor** scrolls to and highlights the exact vulnerable lines.
   - Open the **💡 Evidence Explainability** tab to inspect:
     - **Root Cause Analysis (Why)**
     - **Supporting CWE & CVE Definitions**
     - **Correlated PrimeVul Code Example**
     - **OWASP Remediation Guidance & References**

4. **Review & Apply Security Patches (`--- a/ +++ b/`)**:
   - Open the **🛠️ Unified Diff Patch** tab to see the auto-generated git diff for the selected finding.
   - Click **`🛡️ Apply Patch to Disk File`** to safely apply the verified patch directly to the source file on disk! The AST engine will re-verify the patch structure to ensure safety.

5. **Interactive AI Forensics Chat**:
   - Open the **💬 AI Forensics Chat** tab.
   - Type questions like `"Why is strcpy considered dangerous in this context and how can I fix it?"`
   - The chat panel uses `PromptBuilderModule` to ground queries in your active code snippet and retrieved RAG threat intelligence.
   - **Offline Guard**: If your LLM backend (`Ollama` / `OpenAI-compatible`) is unreachable, the system returns a clear error message explaining that offline simulation is disabled (`No simulated security chat when offline`).

6. **Searchable History & Scan Logs**:
   - Open **🕒 Scan History** to see all past project scans stored in SQLite (`database/forensics_ide.db`). Double-click any past run to instantly load and inspect its saved vulnerabilities!
   - Open **⚙️ Settings** to switch LLM providers (`ollama`, `openai_compatible`, `huggingface_lora`), update endpoints, and adjust thresholds.

---

## 🧪 Running the 100% Verified Unit Test Suite

We have included a comprehensive unit test suite (`tests/test_modules.py`) that thoroughly verifies all 10 modules independently as well as the complete end-to-end integration pipeline:

```powershell
python -m unittest tests/test_modules.py -v
```

**Expected Output**:
```text
test_01_config_manager (tests.test_modules.TestModularSecurityIDE.test_01_config_manager) ... ok
test_02_plugins (tests.test_modules.TestModularSecurityIDE.test_02_plugins) ... ok
test_03_dataset_preprocessing (tests.test_modules.TestModularSecurityIDE.test_03_dataset_preprocessing) ... ok
test_04_fine_tuning (tests.test_modules.TestModularSecurityIDE.test_04_fine_tuning) ... ok
test_05_ast_parser_incremental (tests.test_modules.TestModularSecurityIDE.test_05_ast_parser_incremental) ... ok
test_06_embeddings_and_rag (tests.test_modules.TestModularSecurityIDE.test_06_embeddings_and_rag) ... ok
test_07_prompt_builder (tests.test_modules.TestModularSecurityIDE.test_07_prompt_builder) ... ok
test_08_llm_engine_offline (tests.test_modules.TestModularSecurityIDE.test_08_llm_engine_offline) ... ok
test_09_correlation_verification_explainability (tests.test_modules.TestModularSecurityIDE.test_09_correlation_verification_explainability) ... ok
test_10_patch_and_persistence (tests.test_modules.TestModularSecurityIDE.test_10_patch_and_persistence) ... ok

----------------------------------------------------------------------
Ran 10 tests in ~20.3s

OK
```

---

## 📂 Project Directory Structure

```text
Tree Sitter Demo/
├── ide_app.py                       # Main application entry point (Launches Desktop IDE)
├── config.json                      # Global runtime configuration and thresholds
├── config_manager.py                # Thread-safe Configuration Manager (Singleton)
├── requirements.txt                 # Python dependency declarations
├── README.md                        # Documentation and usage guide
├── plugins/                         # Multi-Language Plugin Registry
│   ├── __init__.py                  # Plugin Loader & Registry (`get_plugin_registry`)
│   ├── c_plugin.py                  # C language plugin & taint signatures (`strcpy`, `gets`, etc.)
│   ├── cpp_plugin.py                # C++ language plugin & taint signatures
│   ├── python_plugin.py             # Python language plugin & taint signatures (`eval`, `exec`, etc.)
│   ├── java_plugin.py               # Java language plugin & taint signatures
│   ├── javascript_plugin.py         # JavaScript language plugin & taint signatures
│   └── typescript_plugin.py         # TypeScript language plugin & taint signatures
├── modules/                         # Core Architecture Modules (`10/10` Modularity)
│   ├── dataset_preprocessing.py     # Juliet/OWASP/NVD deduplication & training JSONL pipeline
│   ├── fine_tuning.py               # LoRA / peft fine-tuning adapter pipeline
│   ├── parser.py                    # Tree-sitter AST & sub-100ms Incremental Scanning Engine
│   ├── embeddings.py                # SentenceTransformer & vector matrix indexing engine
│   ├── rag.py                       # Cosine similarity RAG vector retrieval engine
│   ├── prompt_builder.py            # Dynamic prompt builder & token budgeting (`max_input_tokens = 3500`)
│   ├── llm_engine.py                # Ollama/OpenAI/LoRA inference engine + Strict Offline Guard
│   ├── correlation.py               # AST to RAG threat intelligence binding
│   ├── verification.py              # CVSS 3.1 metric normalization & confidence calculation (`0-100%`)
│   ├── explainability.py            # Structured evidence formatter (`Why -> CWE -> CVE -> OWASP`)
│   ├── patch_generation.py          # Unified diff generator (`--- a/ +++ b/`) & AST safety checker
│   ├── persistence.py               # Thread-safe SQLite relational database manager
│   └── ui_desktop.py                # Rich multi-paned Tkinter/TTK graphical application shell
├── tests/                           # Verification & Test Suite
│   └── test_modules.py              # Automated 10-module unit tests (`100% Pass`)
├── code_samples/                    # Sample vulnerable source files for testing scans
└── database/                        # Local SQLite database storage (`forensics_ide.db`)
```
