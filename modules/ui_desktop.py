from __future__ import annotations

import os
import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Any, Dict, List, Optional

from config_manager import ConfigManager
from modules.correlation import CorrelationModule
from modules.explainability import ExplainabilityModule
from modules.llm_engine import LLMEngine, LLMBackendOfflineError
from modules.parser import ASTParserModule
from modules.patch_generation import PatchGenerationModule
from modules.persistence import PersistenceModule
from modules.prompt_builder import PromptBuilderModule
from modules.verification import VerificationModule


class SecureCodeForensicsIDE(tk.Tk):
    """AI-Powered Secure Code Forensics IDE Desktop Application Shell."""

    THEME = {
        "bg": "#1e1e2e",
        "panel_bg": "#181825",
        "fg": "#cdd6f4",
        "accent": "#cba6f7",
        "select_bg": "#313244",
        "critical": "#f38ba8",
        "high": "#fab387",
        "medium": "#f9e2af",
        "low": "#a6e3a1",
        "info": "#89b4fa",
        "font_family": "Consolas",
    }

    def __init__(self):
        super().__init__()
        self.title("Secure Code Forensics IDE - AI-Powered Modular Forensics")
        self.geometry("1480x880")
        self.minsize(1100, 700)
        self.configure(bg=self.THEME["bg"])

        # Core Modules
        self.config_mgr = ConfigManager.get_instance()
        self.parser_module = ASTParserModule()
        self.prompt_builder = PromptBuilderModule()
        self.llm_engine = LLMEngine(self.prompt_builder)
        self.correlation_module = CorrelationModule()
        self.verification_module = VerificationModule()
        self.explainability_module = ExplainabilityModule()
        self.patch_module = PatchGenerationModule(self.parser_module)
        self.persistence = PersistenceModule.get_instance()

        # State
        self.current_project_folder: Optional[str] = None
        self.current_project_id: Optional[int] = None
        self.current_scan_id: Optional[int] = None
        self.active_file_path: Optional[str] = None
        self.active_finding: Optional[Dict[str, Any]] = None
        self.vulnerabilities_list: List[Dict[str, Any]] = []
        self.file_badges: Dict[str, str] = {}
        self.is_scanning = False
        self.incremental_var = tk.BooleanVar(value=True)

        self._apply_ttk_styles()
        self._build_toolbar()
        self._build_main_layout()
        self._build_status_bar()

        # Load initial history if available
        self._refresh_history_table()

    def _apply_ttk_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=self.THEME["bg"], foreground=self.THEME["fg"], font=(self.THEME["font_family"], 10))
        style.configure("TFrame", background=self.THEME["bg"])
        style.configure("TLabel", background=self.THEME["bg"], foreground=self.THEME["fg"])
        style.configure("TButton", background=self.THEME["select_bg"], foreground=self.THEME["fg"], padding=6, borderwidth=1)
        style.map("TButton", background=[("active", self.THEME["accent"])], foreground=[("active", "#11111b")])
        style.configure("TCheckbutton", background=self.THEME["bg"], foreground=self.THEME["fg"])
        style.configure("Treeview", background=self.THEME["panel_bg"], foreground=self.THEME["fg"], fieldbackground=self.THEME["panel_bg"], rowheight=24)
        style.map("Treeview", background=[("selected", self.THEME["accent"])], foreground=[("selected", "#11111b")])
        style.configure("Treeview.Heading", background=self.THEME["select_bg"], foreground=self.THEME["fg"], font=(self.THEME["font_family"], 10, "bold"))
        style.configure("TNotebook", background=self.THEME["bg"], tabmargins=[2, 5, 2, 0])
        style.configure("TNotebook.Tab", background=self.THEME["select_bg"], foreground=self.THEME["fg"], padding=[12, 4])
        style.map("TNotebook.Tab", background=[("selected", self.THEME["accent"])], foreground=[("selected", "#11111b")])

    def _build_toolbar(self):
        toolbar = ttk.Frame(self, padding=8)
        toolbar.pack(side=tk.TOP, fill=tk.X)

        ttk.Button(toolbar, text="📁 Open Project Folder", command=self._open_project_folder).pack(side=tk.LEFT, padx=4)
        self.scan_btn = ttk.Button(toolbar, text="🚀 Run Security Scan", command=self._start_scan_thread)
        self.scan_btn.pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(toolbar, text="⚡ Incremental Mode [Sub-100ms Cache]", variable=self.incremental_var).pack(side=tk.LEFT, padx=12)

        ttk.Button(toolbar, text="⚙️ Settings", command=self._open_settings_dialog).pack(side=tk.RIGHT, padx=4)
        ttk.Button(toolbar, text="🕒 Searchable History", command=lambda: self.notebook.select(self.tab_history)).pack(side=tk.RIGHT, padx=4)
        ttk.Button(toolbar, text="📊 Scan Logs", command=lambda: self.notebook.select(self.tab_logs)).pack(side=tk.RIGHT, padx=4)

        self.folder_lbl = ttk.Label(toolbar, text="No Project Opened", foreground="#a6adc8", font=(self.THEME["font_family"], 10, "italic"))
        self.folder_lbl.pack(side=tk.LEFT, padx=16)

    def _build_main_layout(self):
        main_paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_paned.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=4)

        # Left: Project Explorer Tree
        left_frame = ttk.Frame(main_paned, width=320)
        main_paned.add(left_frame, weight=1)

        ttk.Label(left_frame, text="📁 PROJECT EXPLORER", font=(self.THEME["font_family"], 11, "bold")).pack(anchor=tk.W, pady=4)
        self.file_tree = ttk.Treeview(left_frame, columns=("badge",), displaycolumns=("badge",))
        self.file_tree.heading("#0", text="File Tree", anchor=tk.W)
        self.file_tree.heading("badge", text="Issues", anchor=tk.CENTER)
        self.file_tree.column("#0", width=220)
        self.file_tree.column("badge", width=70, anchor=tk.CENTER)
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.file_tree.bind("<<TreeviewSelect>>", self._on_file_tree_select)

        tree_scroll = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_tree.configure(yscrollcommand=tree_scroll.set)

        # Right Paned: Top Center (Code Editor) + Bottom (Tabs: Problems, Explainability, Patch, Chat, Logs, History)
        right_paned = ttk.PanedWindow(main_paned, orient=tk.VERTICAL)
        main_paned.add(right_paned, weight=4)

        # Top: Code Editor
        editor_frame = ttk.Frame(right_paned)
        right_paned.add(editor_frame, weight=3)

        editor_header = ttk.Frame(editor_frame)
        editor_header.pack(fill=tk.X, pady=2)
        self.editor_title = ttk.Label(editor_header, text="📄 SOURCE EDITOR (Select a file or problem)", font=(self.THEME["font_family"], 11, "bold"))
        self.editor_title.pack(side=tk.LEFT)

        self.code_text = tk.Text(
            editor_frame,
            bg=self.THEME["panel_bg"],
            fg=self.THEME["fg"],
            insertbackground=self.THEME["accent"],
            font=(self.THEME["font_family"], 11),
            wrap=tk.NONE,
            padx=8,
            pady=8,
        )
        self.code_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.code_text.tag_configure("vuln_highlight", background="#452632", foreground="#f38ba8", font=(self.THEME["font_family"], 11, "bold"))

        code_scroll_y = ttk.Scrollbar(editor_frame, orient=tk.VERTICAL, command=self.code_text.yview)
        code_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.code_text.configure(yscrollcommand=code_scroll_y.set)

        # Bottom: Notebook Tabs
        bottom_frame = ttk.Frame(right_paned)
        right_paned.add(bottom_frame, weight=3)

        self.notebook = ttk.Notebook(bottom_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.tab_problems = ttk.Frame(self.notebook)
        self.tab_explain = ttk.Frame(self.notebook)
        self.tab_patch = ttk.Frame(self.notebook)
        self.tab_chat = ttk.Frame(self.notebook)
        self.tab_logs = ttk.Frame(self.notebook)
        self.tab_history = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_problems, text="🚨 Problems Table")
        self.notebook.add(self.tab_explain, text="💡 Evidence Explainability")
        self.notebook.add(self.tab_patch, text="🛠️ Unified Diff Patch")
        self.notebook.add(self.tab_chat, text="💬 AI Forensics Chat")
        self.notebook.add(self.tab_logs, text="📊 Scan Diagnostics")
        self.notebook.add(self.tab_history, text="🕒 Scan History")

        self._init_problems_tab()
        self._init_explain_tab()
        self._init_patch_tab()
        self._init_chat_tab()
        self._init_logs_tab()
        self._init_history_tab()

    def _build_status_bar(self):
        self.status_bar = ttk.Label(
            self, text="Status: Ready | Engine: Multi-Language Tree-sitter + RAG + LoRA Engine", relief=tk.SUNKEN, padding=4
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _init_problems_tab(self):
        cols = ("severity", "confidence", "cwe", "function", "file", "line")
        self.problems_table = ttk.Treeview(self.tab_problems, columns=cols, show="headings")
        self.problems_table.heading("severity", text="Severity")
        self.problems_table.heading("confidence", text="Conf %")
        self.problems_table.heading("cwe", text="CWE / CVE")
        self.problems_table.heading("function", text="Function")
        self.problems_table.heading("file", text="File Path")
        self.problems_table.heading("line", text="Lines")

        self.problems_table.column("severity", width=80, anchor=tk.CENTER)
        self.problems_table.column("confidence", width=70, anchor=tk.CENTER)
        self.problems_table.column("cwe", width=120, anchor=tk.CENTER)
        self.problems_table.column("function", width=140)
        self.problems_table.column("file", width=260)
        self.problems_table.column("line", width=70, anchor=tk.CENTER)

        self.problems_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.problems_table.bind("<<TreeviewSelect>>", self._on_problem_select)

        scroll = ttk.Scrollbar(self.tab_problems, orient=tk.VERTICAL, command=self.problems_table.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.problems_table.configure(yscrollcommand=scroll.set)

    def _init_explain_tab(self):
        self.explain_text = tk.Text(
            self.tab_explain, bg=self.THEME["panel_bg"], fg=self.THEME["fg"], font=(self.THEME["font_family"], 11), wrap=tk.WORD, padx=10, pady=10
        )
        self.explain_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(self.tab_explain, orient=tk.VERTICAL, command=self.explain_text.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.explain_text.configure(yscrollcommand=scroll.set)

    def _init_patch_tab(self):
        top = ttk.Frame(self.tab_patch)
        top.pack(fill=tk.X, pady=4, padx=6)
        self.apply_patch_btn = ttk.Button(top, text="🛡️ Apply Patch to Disk File", command=self._apply_active_patch, state=tk.DISABLED)
        self.apply_patch_btn.pack(side=tk.LEFT)
        self.patch_status_lbl = ttk.Label(top, text="Select a problem to generate or preview patch diff", font=(self.THEME["font_family"], 10, "italic"))
        self.patch_status_lbl.pack(side=tk.LEFT, padx=12)

        self.patch_diff_text = tk.Text(
            self.tab_patch, bg="#11111b", fg="#a6e3a1", font=(self.THEME["font_family"], 10), wrap=tk.NONE, padx=10, pady=10
        )
        self.patch_diff_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(self.tab_patch, orient=tk.VERTICAL, command=self.patch_diff_text.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.patch_diff_text.configure(yscrollcommand=scroll.set)

    def _init_chat_tab(self):
        self.chat_display = tk.Text(
            self.tab_chat, bg=self.THEME["panel_bg"], fg=self.THEME["fg"], font=(self.THEME["font_family"], 11), wrap=tk.WORD, padx=10, pady=10
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True)

        input_frame = ttk.Frame(self.tab_chat)
        input_frame.pack(fill=tk.X, pady=4, padx=4)
        self.chat_entry = ttk.Entry(input_frame, font=(self.THEME["font_family"], 11))
        self.chat_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.chat_entry.bind("<Return>", lambda e: self._send_chat_question())
        ttk.Button(input_frame, text="Send 🚀", command=self._send_chat_question).pack(side=tk.RIGHT, padx=4)

    def _init_logs_tab(self):
        self.logs_text = tk.Text(
            self.tab_logs, bg="#11111b", fg="#bac2de", font=(self.THEME["font_family"], 10), wrap=tk.WORD, padx=8, pady=8
        )
        self.logs_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(self.tab_logs, orient=tk.VERTICAL, command=self.logs_text.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.logs_text.configure(yscrollcommand=scroll.set)

    def _init_history_tab(self):
        cols = ("id", "timestamp", "folder", "files", "findings")
        self.history_table = ttk.Treeview(self.tab_history, columns=cols, show="headings")
        self.history_table.heading("id", text="Scan ID")
        self.history_table.heading("timestamp", text="Timestamp")
        self.history_table.heading("folder", text="Project Folder")
        self.history_table.heading("files", text="Files Scanned")
        self.history_table.heading("findings", text="Findings Count")

        self.history_table.column("id", width=60, anchor=tk.CENTER)
        self.history_table.column("timestamp", width=160, anchor=tk.CENTER)
        self.history_table.column("folder", width=400)
        self.history_table.column("files", width=100, anchor=tk.CENTER)
        self.history_table.column("findings", width=120, anchor=tk.CENTER)

        self.history_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.history_table.bind("<Double-1>", self._on_history_double_click)

        scroll = ttk.Scrollbar(self.tab_history, orient=tk.VERTICAL, command=self.history_table.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.history_table.configure(yscrollcommand=scroll.set)

    # Actions & Threading
    def _open_project_folder(self):
        folder = filedialog.askdirectory(title="Select Project Folder to Analyze")
        if not folder:
            return
        self.current_project_folder = os.path.abspath(folder)
        self.folder_lbl.configure(text=f"Folder: {self.current_project_folder}")
        self.current_project_id = self.persistence.register_or_get_project(self.current_project_folder)
        self._populate_file_tree(self.current_project_folder)
        self._log_msg(f"Opened project: {self.current_project_folder} (ID: {self.current_project_id})")

    def _populate_file_tree(self, root_path: str):
        self.file_tree.delete(*self.file_tree.get_children())
        node_map = {}

        for root, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if not self.config_mgr.is_ignored_dir(d)]
            rel_path = os.path.relpath(root, root_path)
            parent_id = "" if rel_path == "." else node_map.get(os.path.dirname(rel_path) if os.path.dirname(rel_path) else "", "")

            if rel_path != ".":
                dir_id = self.file_tree.insert(parent_id, "end", text=f"📁 {os.path.basename(root)}", open=True)
                node_map[rel_path] = dir_id
            else:
                dir_id = ""
                node_map[""] = ""

            for f in sorted(files):
                ext = os.path.splitext(f)[1].lower()
                if self.config_mgr.is_supported_extension(ext):
                    full_f = os.path.join(root, f)
                    badge = self.file_badges.get(full_f, "")
                    self.file_tree.insert(dir_id, "end", text=f"📄 {f}", values=(badge,), tags=(full_f,))

    def _start_scan_thread(self):
        if not self.current_project_folder:
            messagebox.showwarning("No Project", "Please open a project folder first via 'Open Project Folder'.")
            return
        if self.is_scanning:
            return

        self.is_scanning = True
        self.scan_btn.configure(state=tk.DISABLED, text="⏳ Scanning Project...")
        self.status_bar.configure(text="Status: Scanning multi-language Tree-sitter AST and correlating with RAG threat intelligence...")

        threading.Thread(target=self._run_scan_pipeline, daemon=True).start()

    def _run_scan_pipeline(self):
        try:
            import time
            start_t = time.time()
            force_reparse = not self.incremental_var.get()
            self._log_msg(f"Starting scan on {self.current_project_folder} (Incremental: {not force_reparse})...")

            # 1. AST Parser Scan
            parser_res = self.parser_module.scan_project(self.current_project_folder, force_reparse=force_reparse)
            file_results = parser_res.get("file_results", {})

            # 2. Create database scan run
            scanned_files_count = parser_res.get("files_scanned", 0)
            self.current_scan_id = self.persistence.create_scan_run(self.current_project_id or 1, scanned_files_count, 0)

            all_verified_findings: List[Dict[str, Any]] = []
            self.file_badges.clear()

            # 3. Correlate and Verify Findings
            for fpath, analysis in file_results.items():
                lang = analysis.get("language", "unknown")
                correlated = self.correlation_module.correlate_file_findings(fpath, lang, analysis)
                file_issue_count = 0

                for corr in correlated:
                    # Optional LLM verification pass if online
                    llm_resp = {}
                    try:
                        conn_status = self.llm_engine.check_connection()
                        if conn_status.get("status") == "ONLINE":
                            prompt = self.prompt_builder.build_verification_prompt(corr, corr.get("rag_context", {}), lang)
                            llm_resp = self.llm_engine.execute_inference(prompt)
                    except Exception as exc:
                        pass

                    verified = self.verification_module.verify_finding(corr, llm_resp)
                    if verified.get("severity") != "Info" and verified.get("confidence", 0) >= 40:
                        # Generate patch preview
                        patch_info = self.patch_module.generate_patch_for_finding(verified)
                        verified["patch_diff"] = patch_info.get("unified_diff", "")
                        verified["patched_snippet"] = patch_info.get("patched_snippet", "")
                        verified["explanation_json"] = self.explainability_module.generate_evidence_explanation(verified)

                        all_verified_findings.append(verified)
                        file_issue_count += 1

                if file_issue_count > 0:
                    self.file_badges[fpath] = f"🔴 {file_issue_count}"

            # 4. Save to SQLite
            self.persistence.save_vulnerabilities(self.current_scan_id, all_verified_findings)
            self.persistence.update_scan_findings_count(self.current_scan_id, len(all_verified_findings))
            self.vulnerabilities_list = sorted(all_verified_findings, key=lambda x: (x.get("cvss_score", 0), x.get("confidence", 0)), reverse=True)

            elapsed = round(time.time() - start_t, 3)
            msg = f"Scan Completed in {elapsed}s! Scanned: {scanned_files_count} files ({parser_res.get('files_from_cache', 0)} from cache). Verified Findings: {len(self.vulnerabilities_list)}"
            self._log_msg(msg)
            self.persistence.log_scan_message(self.current_scan_id, msg)

            self.after(10, lambda: self._on_scan_completed(msg))
        except Exception as exc:
            self.after(10, lambda: self._on_scan_error(str(exc)))

    def _on_scan_completed(self, status_msg: str):
        self.is_scanning = False
        self.scan_btn.configure(state=tk.NORMAL, text="🚀 Run Security Scan")
        self.status_bar.configure(text=f"Status: {status_msg}")
        self._populate_file_tree(self.current_project_folder)
        self._refresh_problems_table()
        self._refresh_history_table()
        self.notebook.select(self.tab_problems)

    def _on_scan_error(self, error_msg: str):
        self.is_scanning = False
        self.scan_btn.configure(state=tk.NORMAL, text="🚀 Run Security Scan")
        self.status_bar.configure(text=f"Status Error: {error_msg}")
        self._log_msg(f"Scan failed: {error_msg}", level="ERROR")
        messagebox.showerror("Scan Error", f"Security scan encountered an error:\n{error_msg}")

    def _refresh_problems_table(self):
        self.problems_table.delete(*self.problems_table.get_children())
        for idx, item in enumerate(self.vulnerabilities_list):
            sev = item.get("severity", "High")
            conf = item.get("confidence", 65)
            cwe = f"{item.get('cwe', 'Unknown')} ({item.get('cve', 'Unknown')})"
            func = item.get("function_name", "unknown")
            fpath = os.path.relpath(item.get("file_path", ""), self.current_project_folder) if self.current_project_folder else item.get("file_path", "")
            lines = f"{item.get('start_line', 1)}-{item.get('end_line', 1)}"

            self.problems_table.insert("", "end", iid=str(idx), values=(sev, f"{conf}%", cwe, func, fpath, lines))

    def _refresh_history_table(self):
        self.history_table.delete(*self.history_table.get_children())
        history = self.persistence.list_scan_history(self.current_project_id)
        for h in history:
            self.history_table.insert(
                "", "end", values=(h.get("id"), h.get("timestamp", "")[:19].replace("T", " "), os.path.basename(h.get("folder_path", "")), h.get("file_count", 0), h.get("findings_count", 0))
            )

    # Selection & Editor Display
    def _on_file_tree_select(self, event):
        selected = self.file_tree.selection()
        if not selected:
            return
        tags = self.file_tree.item(selected[0], "tags")
        if tags and os.path.isfile(tags[0]):
            self._display_file_in_editor(tags[0])

    def _display_file_in_editor(self, file_path: str, highlight_line: Optional[int] = None):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            self.active_file_path = file_path
            self.editor_title.configure(text=f"📄 SOURCE EDITOR: {file_path}")

            self.code_text.delete("1.0", tk.END)
            self.code_text.insert("1.0", content)

            if highlight_line and highlight_line > 0:
                start_idx = f"{highlight_line}.0"
                end_idx = f"{highlight_line}.end"
                self.code_text.tag_add("vuln_highlight", start_idx, end_idx)
                self.code_text.see(start_idx)
        except Exception as exc:
            self._log_msg(f"Could not read file {file_path}: {exc}", level="WARNING")

    def _on_problem_select(self, event):
        selected = self.problems_table.selection()
        if not selected:
            return
        idx = int(selected[0])
        if 0 <= idx < len(self.vulnerabilities_list):
            item = self.vulnerabilities_list[idx]
            self.active_finding = item

            # 1. Open and highlight in code editor
            fpath = item.get("file_path", "")
            if os.path.exists(fpath):
                self._display_file_in_editor(fpath, highlight_line=item.get("start_line", 1))

            # 2. Show Explainability breakdown
            exp = item.get("explanation_json", {})
            md_text = exp.get("markdown_report", "") if isinstance(exp, dict) else ""
            if not md_text:
                md_text = f"### Root Cause Analysis\n{item.get('sink')} vulnerability in {item.get('function_name')}\n\nSeverity: {item.get('severity')} | CVSS: {item.get('cvss_score')} | Confidence: {item.get('confidence')}%"

            self.explain_text.delete("1.0", tk.END)
            self.explain_text.insert("1.0", md_text)

            # 3. Show Unified Diff Patch
            diff_text = item.get("patch_diff", "")
            self.patch_diff_text.delete("1.0", tk.END)
            if diff_text:
                self.patch_diff_text.insert("1.0", diff_text)
                self.apply_patch_btn.configure(state=tk.NORMAL)
                self.patch_status_lbl.configure(text=f"Ready to apply fix for {item.get('cwe')} in {os.path.basename(fpath)}")
            else:
                self.patch_diff_text.insert("1.0", "// No automated unified diff generated for this finding.")
                self.apply_patch_btn.configure(state=tk.DISABLED)

    def _on_history_double_click(self, event):
        selected = self.history_table.selection()
        if not selected:
            return
        vals = self.history_table.item(selected[0], "values")
        if vals:
            scan_id = int(vals[0])
            loaded_vulns = self.persistence.get_scan_vulnerabilities(scan_id)
            self.vulnerabilities_list = loaded_vulns
            self._refresh_problems_table()
            self.notebook.select(self.tab_problems)
            self._log_msg(f"Loaded {len(loaded_vulns)} historical vulnerabilities from Scan ID {scan_id}")

    def _apply_active_patch(self):
        if not self.active_finding or not self.active_finding.get("patched_snippet"):
            return
        fpath = self.active_finding.get("file_path", "")
        if not os.path.exists(fpath):
            messagebox.showerror("Error", f"Target file does not exist: {fpath}")
            return

        orig_snip = self.active_finding.get("correlated_item", {}).get("full_snippet", "")
        patched_snip = self.active_finding.get("patched_snippet", "")

        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
            if orig_snip and orig_snip in content:
                new_content = content.replace(orig_snip, patched_snip, 1)
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(new_content)
                messagebox.showinfo("Patch Applied", f"Successfully applied security patch to:\n{fpath}")
                self._display_file_in_editor(fpath, highlight_line=self.active_finding.get("start_line", 1))
                self._log_msg(f"Applied security patch to {fpath}")
            else:
                messagebox.showwarning("Patch Alignment", "Original snippet mismatch in file; could not auto-apply. Please review unified diff.")
        except Exception as exc:
            messagebox.showerror("Write Error", f"Failed to apply patch: {exc}")

    def _send_chat_question(self):
        question = self.chat_entry.get().strip()
        if not question:
            return
        self.chat_entry.delete(0, tk.END)
        self.chat_display.insert(tk.END, f"\nUser: {question}\n")
        self.chat_display.see(tk.END)

        code_ctx = self.code_text.get("1.0", tk.END)[:1500] if self.active_file_path else "No active file opened."
        rag_ctx = self.active_finding.get("correlated_item", {}).get("rag_context", {}) if self.active_finding else {}

        # Check offline requirement
        conn = self.llm_engine.check_connection()
        if conn.get("status") != "ONLINE":
            self.chat_display.insert(
                tk.END,
                f"AI: [LLM Backend Offline ({conn.get('provider')})]\n"
                f"Cannot generate dynamic response while offline (Strict rule: no simulated security chat). "
                f"Please ensure Ollama or local LLM is running on {conn.get('endpoint', 'port 11434')} or switch providers in Settings.\n",
            )
            self.chat_display.see(tk.END)
            return

        def run_chat():
            try:
                prompt = self.prompt_builder.build_chat_prompt(question, code_ctx, "c", rag_ctx)
                ans_text = ""
                self.chat_display.insert(tk.END, "AI: ")
                for token in self.llm_engine.stream_chat(prompt):
                    ans_text += token
                    self.chat_display.insert(tk.END, token)
                    self.chat_display.see(tk.END)
                self.chat_display.insert(tk.END, "\n")
                if self.current_project_id:
                    self.persistence.save_chat_message(self.current_project_id, question, ans_text, {"file": self.active_file_path})
            except LLMBackendOfflineError as exc:
                self.chat_display.insert(tk.END, f"\n[Backend Error]: {exc}\n")
                self.chat_display.see(tk.END)

        threading.Thread(target=run_chat, daemon=True).start()

    def _open_settings_dialog(self):
        win = tk.Toplevel(self)
        win.title("Forensics IDE Settings")
        win.geometry("500x380")
        win.configure(bg=self.THEME["bg"])

        ttk.Label(win, text="LLM Provider:", font=(self.THEME["font_family"], 10, "bold")).pack(anchor=tk.W, padx=12, pady=(12, 2))
        provider_var = tk.StringVar(value=self.config_mgr.get("llm_provider", "ollama"))
        provider_combo = ttk.Combobox(win, textvariable=provider_var, values=["ollama", "openai_compatible", "huggingface_lora"])
        provider_combo.pack(fill=tk.X, padx=12)

        ttk.Label(win, text="LLM Endpoint URL:", font=(self.THEME["font_family"], 10, "bold")).pack(anchor=tk.W, padx=12, pady=(12, 2))
        endpoint_var = tk.StringVar(value=self.config_mgr.get("llm_endpoint", "http://localhost:11434/api/chat"))
        ttk.Entry(win, textvariable=endpoint_var).pack(fill=tk.X, padx=12)

        ttk.Label(win, text="Model Name / LoRA Path:", font=(self.THEME["font_family"], 10, "bold")).pack(anchor=tk.W, padx=12, pady=(12, 2))
        model_var = tk.StringVar(value=self.config_mgr.get("llm_model", "deepseek-coder:6.7b"))
        ttk.Entry(win, textvariable=model_var).pack(fill=tk.X, padx=12)

        def save_and_close():
            self.config_mgr.set("llm_provider", provider_var.get())
            self.config_mgr.set("llm_endpoint", endpoint_var.get())
            self.config_mgr.set("llm_model", model_var.get())
            self.config_mgr.save_config()
            self._log_msg(f"Settings updated: Provider={provider_var.get()}, Model={model_var.get()}")
            win.destroy()

        ttk.Button(win, text="💾 Save Settings", command=save_and_close).pack(pady=24)

    def _log_msg(self, msg: str, level: str = "INFO"):
        time_str = datetime.now().strftime("%H:%M:%S")
        self.logs_text.insert(tk.END, f"[{time_str}] [{level}] {msg}\n")
        self.logs_text.see(tk.END)
