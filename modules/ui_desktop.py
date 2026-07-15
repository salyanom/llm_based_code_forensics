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


# ─────────────────────────────────────────────────────────────────────────────
#  VS Code Dark Design Tokens
# ─────────────────────────────────────────────────────────────────────────────
C = {
    "bg_editor":     "#1e1e1e",
    "bg_sidebar":    "#252526",
    "bg_activity":   "#333333",
    "bg_tab_active": "#1e1e1e",
    "bg_tab_idle":   "#2d2d2d",
    "bg_titlebar":   "#3c3c3c",
    "bg_statusbar":  "#007acc",
    "bg_input":      "#3c3c3c",
    "bg_hover":      "#2a2d2e",
    "bg_select":     "#094771",
    "bg_vuln":       "#3a1515",
    "bg_right":      "#1f1f1f",
    "bg_progress":   "#252526",
    "fg_default":    "#d4d4d4",
    "fg_muted":      "#858585",
    "fg_title":      "#ffffff",
    "fg_accent":     "#569cd6",
    "fg_green":      "#4ec9b0",
    "fg_yellow":     "#dcdcaa",
    "fg_orange":     "#ce9178",
    "fg_red":        "#f44747",
    "fg_vuln":       "#ff6b6b",
    "sev_critical":  "#f44747",
    "sev_high":      "#d78700",
    "sev_medium":    "#dcdcaa",
    "sev_low":       "#4ec9b0",
    "border":        "#454545",
    "cursor":        "#aeafad",
    "font_mono":     "Consolas",
    "font_ui":       "Segoe UI",
    "font_size":     10,
}

SEV_COLORS = {
    "Critical": C["sev_critical"],
    "High":     C["sev_high"],
    "Medium":   C["sev_medium"],
    "Low":      C["sev_low"],
    "Info":     C["fg_muted"],
}

SCAN_STAGES = [
    ("parse",    "Parsing AST…"),
    ("correlate","Correlating RAG…"),
    ("llm",      "LLM Verification…"),
    ("verify",   "Computing CVSS…"),
    ("patch",    "Generating Patches…"),
    ("explain",  "Building Evidence…"),
    ("persist",  "Saving to Database…"),
    ("done",     "Scan Complete"),
]


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────
class _LineNumberCanvas(tk.Canvas):
    def __init__(self, master, text_widget: tk.Text, **kw):
        super().__init__(master, width=52, bg=C["bg_sidebar"], highlightthickness=0, **kw)
        self._text = text_widget
        for evt in ("<Configure>", "<KeyRelease>", "<<Modified>>", "<MouseWheel>"):
            self._text.bind(evt, self._on_change)

    def _on_change(self, _=None):
        self.after_idle(self._redraw)

    def _redraw(self):
        self.delete("all")
        i = self._text.index("@0,0")
        while True:
            bbox = self._text.dlineinfo(i)
            if bbox is None:
                break
            lineno = str(i).split(".")[0]
            self.create_text(46, bbox[1] + 1, anchor="ne", text=lineno,
                             fill=C["fg_muted"], font=(C["font_mono"], C["font_size"] - 1))
            i = self._text.index(f"{i}+1line")
            if i == self._text.index(f"{i}"):
                break


class _FlatBtn(tk.Label):
    def __init__(self, master, text: str, command=None, accent=False, icon="", **kw):
        fg = C["fg_accent"] if accent else C["fg_default"]
        label = f"  {icon}  {text}  " if icon else f"  {text}  "
        super().__init__(master, text=label, bg=C["bg_titlebar"], fg=fg,
                         font=(C["font_ui"], C["font_size"]), cursor="hand2",
                         padx=4, pady=5, **kw)
        self._cmd = command
        self.bind("<Enter>", lambda _: self.config(bg="#505050"))
        self.bind("<Leave>", lambda _: self.config(bg=C["bg_titlebar"]))
        self.bind("<Button-1>", lambda _: self._cmd() if self._cmd else None)

    def set_enabled(self, v: bool):
        self.config(fg=(C["fg_accent"] if v else C["fg_muted"]),
                    cursor=("hand2" if v else ""))


class _ActBtn(tk.Label):
    def __init__(self, master, icon: str, command=None, **kw):
        super().__init__(master, text=icon, bg=C["bg_activity"], fg=C["fg_muted"],
                         font=(C["font_ui"], 16), cursor="hand2", width=2, pady=10, **kw)
        self._cmd = command
        self.bind("<Enter>", lambda _: self.config(fg=C["fg_title"]))
        self.bind("<Leave>", lambda _: self.config(fg=C["fg_muted"]))
        self.bind("<Button-1>", lambda _: self._cmd() if self._cmd else None)

    def set_active(self, v: bool):
        self.config(fg=C["fg_title"] if v else C["fg_muted"])


class _SectionLabel(tk.Label):
    def __init__(self, master, text: str, **kw):
        super().__init__(master, text=text, bg=C["bg_sidebar"], fg=C["fg_muted"],
                         font=(C["font_ui"], 8, "bold"), anchor="w", padx=12, pady=(8, 4), **kw)


class _Separator(tk.Frame):
    def __init__(self, master, orient="h", **kw):
        if orient == "h":
            super().__init__(master, bg=C["border"], height=1, **kw)
        else:
            super().__init__(master, bg=C["border"], width=1, **kw)


# ─────────────────────────────────────────────────────────────────────────────
#  Scan Progress Overlay Window
# ─────────────────────────────────────────────────────────────────────────────
class ScanProgressWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Scan Progress")
        self.geometry("460x340")
        self.resizable(False, False)
        self.configure(bg=C["bg_progress"])
        self.transient(parent)

        tk.Label(self, text="Security Scan Running", bg=C["bg_progress"], fg=C["fg_title"],
                 font=(C["font_ui"], 13, "bold"), pady=14).pack(fill=tk.X)
        _Separator(self).pack(fill=tk.X)

        self._stage_frames: Dict[str, Dict[str, Any]] = {}
        frame = tk.Frame(self, bg=C["bg_progress"])
        frame.pack(fill=tk.BOTH, expand=True, padx=24, pady=12)

        for key, label in SCAN_STAGES:
            row = tk.Frame(frame, bg=C["bg_progress"])
            row.pack(fill=tk.X, pady=3)
            icon = tk.Label(row, text="○", bg=C["bg_progress"], fg=C["fg_muted"],
                            font=(C["font_ui"], 11), width=2)
            icon.pack(side=tk.LEFT)
            lbl = tk.Label(row, text=label, bg=C["bg_progress"], fg=C["fg_muted"],
                           font=(C["font_ui"], 10), anchor="w")
            lbl.pack(side=tk.LEFT, padx=8)
            sub = tk.Label(row, text="", bg=C["bg_progress"], fg=C["fg_muted"],
                           font=(C["font_ui"], 9, "italic"), anchor="w")
            sub.pack(side=tk.LEFT)
            self._stage_frames[key] = {"icon": icon, "label": lbl, "sub": sub}

        _Separator(self).pack(fill=tk.X)
        self._status = tk.Label(self, text="Initializing…", bg=C["bg_progress"],
                                fg=C["fg_accent"], font=(C["font_ui"], 9, "italic"), pady=8)
        self._status.pack()

    def set_stage(self, key: str, status: str = "running", detail: str = ""):
        """status: 'running' | 'done' | 'skip' | 'error'"""
        if key not in self._stage_frames:
            return
        d = self._stage_frames[key]
        colors = {
            "running": (C["fg_accent"], "►", C["fg_accent"]),
            "done":    (C["fg_green"],  "✓", C["fg_green"]),
            "skip":    (C["fg_muted"],  "–", C["fg_muted"]),
            "error":   (C["fg_red"],    "✗", C["fg_red"]),
        }
        fg, icon_txt, label_fg = colors.get(status, (C["fg_muted"], "○", C["fg_muted"]))
        d["icon"].config(text=icon_txt, fg=fg)
        d["label"].config(fg=label_fg)
        if detail:
            d["sub"].config(text=f"  {detail}", fg=C["fg_muted"])
        label = next((lbl for k, lbl in SCAN_STAGES if k == key), key)
        self._status.config(text=label)
        self.update_idletasks()

    def finish(self, summary: str = ""):
        self._status.config(text=summary or "Done", fg=C["fg_green"])
        self.update_idletasks()


# ─────────────────────────────────────────────────────────────────────────────
#  Main IDE Window
# ─────────────────────────────────────────────────────────────────────────────
class SecureCodeForensicsIDE(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Forensics IDE")
        self.geometry("1700x980")
        self.minsize(1200, 700)
        self.configure(bg=C["bg_editor"])

        # Modules
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
        self._active_panel = "explorer"

        self._apply_styles()
        self._build_ui()
        self._refresh_history_table()

    # ── Styles ─────────────────────────────────────────────────────────────────
    def _apply_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=C["bg_editor"], foreground=C["fg_default"],
                    font=(C["font_ui"], C["font_size"]), borderwidth=0)
        s.configure("TFrame", background=C["bg_editor"])
        s.configure("TLabel", background=C["bg_editor"], foreground=C["fg_default"])
        s.configure("TCheckbutton", background=C["bg_titlebar"], foreground=C["fg_muted"],
                    font=(C["font_ui"], 9))
        s.map("TCheckbutton", background=[("active", C["bg_titlebar"])],
              foreground=[("active", C["fg_default"])])
        s.configure("TCombobox", fieldbackground=C["bg_input"], background=C["bg_input"],
                    foreground=C["fg_default"], arrowcolor=C["fg_muted"])

        for style, bg in [("Explorer.Treeview", C["bg_sidebar"]),
                          ("Problems.Treeview",  C["bg_editor"]),
                          ("History.Treeview",   C["bg_sidebar"])]:
            s.configure(style, background=bg, foreground=C["fg_default"],
                        fieldbackground=bg, rowheight=24, font=(C["font_ui"], 9), borderwidth=0)
            s.map(style, background=[("selected", C["bg_select"])],
                  foreground=[("selected", C["fg_title"])])
            s.configure(f"{style}.Heading", background=bg, foreground=C["fg_muted"],
                        font=(C["font_ui"], 8, "bold"), borderwidth=0)

        for sv in ("Thin.Vertical.TScrollbar", "Thin.Horizontal.TScrollbar"):
            s.configure(sv, background=C["bg_sidebar"], troughcolor=C["bg_editor"],
                        arrowcolor=C["bg_sidebar"], width=8)

    # ── Root Layout ────────────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_titlebar()
        body = tk.Frame(self, bg=C["bg_editor"])
        body.pack(fill=tk.BOTH, expand=True)

        # Activity bar
        self._activity_bar = tk.Frame(body, bg=C["bg_activity"], width=48)
        self._activity_bar.pack(side=tk.LEFT, fill=tk.Y)
        self._activity_bar.pack_propagate(False)
        self._build_activity_bar()

        _Separator(body, orient="v").pack(side=tk.LEFT, fill=tk.Y)

        # Left sidebar
        self._sidebar_frame = tk.Frame(body, bg=C["bg_sidebar"], width=260)
        self._sidebar_frame.pack(side=tk.LEFT, fill=tk.Y)
        self._sidebar_frame.pack_propagate(False)

        _Separator(body, orient="v").pack(side=tk.LEFT, fill=tk.Y)

        # Right detail sidebar
        self._right_sidebar = tk.Frame(body, bg=C["bg_right"], width=320)
        self._right_sidebar.pack(side=tk.RIGHT, fill=tk.Y)
        self._right_sidebar.pack_propagate(False)
        self._build_right_sidebar()

        _Separator(body, orient="v").pack(side=tk.RIGHT, fill=tk.Y)

        # Centre
        centre = tk.Frame(body, bg=C["bg_editor"])
        centre.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._build_sidebar_explorer()
        self._build_main_area(centre)
        self._build_statusbar()

    # ── Titlebar ───────────────────────────────────────────────────────────────
    def _build_titlebar(self):
        bar = tk.Frame(self, bg=C["bg_titlebar"], height=36)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)

        tk.Label(bar, text="  🛡  Forensics IDE", bg=C["bg_titlebar"], fg=C["fg_default"],
                 font=(C["font_ui"], 10, "bold")).pack(side=tk.LEFT)
        _Separator(bar, orient="v").pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=6)

        self._btn_open = _FlatBtn(bar, "Open Folder", command=self._open_project_folder, icon="📁")
        self._btn_open.pack(side=tk.LEFT)

        self._btn_scan = _FlatBtn(bar, "Run Scan", command=self._start_scan_thread, icon="▶", accent=True)
        self._btn_scan.pack(side=tk.LEFT, padx=2)

        _Separator(bar, orient="v").pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=6)

        self._incr_check = ttk.Checkbutton(bar, text="Incremental", variable=self.incremental_var)
        self._incr_check.pack(side=tk.LEFT, padx=4)

        _FlatBtn(bar, "Settings", command=self._open_settings_dialog, icon="⚙").pack(side=tk.RIGHT, padx=2)

        self._folder_lbl = tk.Label(bar, text="No project opened", bg=C["bg_titlebar"],
                                    fg=C["fg_muted"], font=(C["font_ui"], 9, "italic"))
        self._folder_lbl.pack(side=tk.LEFT, padx=12)

    # ── Activity Bar ───────────────────────────────────────────────────────────
    def _build_activity_bar(self):
        self._act_btns: Dict[str, _ActBtn] = {}
        for key, icon in [("explorer","☰"),("problems","⚠"),("history","⏱"),("logs","≡")]:
            btn = _ActBtn(self._activity_bar, icon, command=lambda k=key: self._switch_panel(k))
            btn.pack(fill=tk.X)
            self._act_btns[key] = btn
        self._set_active_btn("explorer")

    def _set_active_btn(self, key: str):
        for k, b in self._act_btns.items():
            b.set_active(k == key)

    # ── Sidebar panels ─────────────────────────────────────────────────────────
    def _build_sidebar_explorer(self):
        self._panel_explorer = tk.Frame(self._sidebar_frame, bg=C["bg_sidebar"])
        _SectionLabel(self._panel_explorer, "EXPLORER").pack(fill=tk.X)
        tf = tk.Frame(self._panel_explorer, bg=C["bg_sidebar"])
        tf.pack(fill=tk.BOTH, expand=True)
        self.file_tree = ttk.Treeview(tf, style="Explorer.Treeview",
                                       columns=("badge",), displaycolumns=("badge",), show="tree")
        self.file_tree.column("#0", width=200)
        self.file_tree.column("badge", width=46, anchor=tk.CENTER)
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.file_tree.bind("<<TreeviewSelect>>", self._on_file_tree_select)
        sb = ttk.Scrollbar(tf, style="Thin.Vertical.TScrollbar", command=self.file_tree.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_tree.configure(yscrollcommand=sb.set)
        self._panel_explorer.pack(fill=tk.BOTH, expand=True)

    def _build_sidebar_problems(self):
        if hasattr(self, "_panel_problems"):
            return
        self._panel_problems = tk.Frame(self._sidebar_frame, bg=C["bg_sidebar"])
        _SectionLabel(self._panel_problems, "PROBLEMS").pack(fill=tk.X)
        self._problems_list = tk.Listbox(
            self._panel_problems, bg=C["bg_sidebar"], fg=C["fg_default"],
            selectbackground=C["bg_select"], selectforeground=C["fg_title"],
            font=(C["font_mono"], 9), relief=tk.FLAT, borderwidth=0, activestyle="none")
        self._problems_list.pack(fill=tk.BOTH, expand=True, padx=2)
        self._problems_list.bind("<<ListboxSelect>>", self._on_sidebar_problem_click)

    def _build_sidebar_history(self):
        if hasattr(self, "_panel_history"):
            return
        self._panel_history = tk.Frame(self._sidebar_frame, bg=C["bg_sidebar"])
        _SectionLabel(self._panel_history, "SCAN HISTORY").pack(fill=tk.X)

        cols = ("id", "time", "files", "issues")
        self.history_table = ttk.Treeview(self._panel_history, style="History.Treeview",
                                           columns=cols, show="headings")
        for col, w, txt in [("id",40,"ID"),("time",120,"Timestamp"),
                             ("files",46,"Files"),("issues",50,"Issues")]:
            self.history_table.heading(col, text=txt)
            self.history_table.column(col, width=w, anchor=tk.CENTER)
        self.history_table.pack(fill=tk.BOTH, expand=True, padx=2)
        self.history_table.bind("<Double-1>", self._on_history_double_click)

    def _build_sidebar_logs(self):
        if hasattr(self, "_panel_logs"):
            return
        self._panel_logs = tk.Frame(self._sidebar_frame, bg=C["bg_sidebar"])
        _SectionLabel(self._panel_logs, "OUTPUT").pack(fill=tk.X)
        self.logs_text = tk.Text(
            self._panel_logs, bg=C["bg_sidebar"], fg=C["fg_muted"],
            font=(C["font_mono"], 8), wrap=tk.WORD, relief=tk.FLAT,
            borderwidth=0, padx=8, pady=4, state=tk.DISABLED)
        self.logs_text.pack(fill=tk.BOTH, expand=True)
        self.logs_text.tag_configure("ERROR",   foreground=C["sev_critical"])
        self.logs_text.tag_configure("WARNING", foreground=C["sev_medium"])
        self.logs_text.tag_configure("INFO",    foreground=C["fg_green"])

    def _switch_panel(self, key: str):
        self._active_panel = key
        self._set_active_btn(key)
        builders = {"problems": self._build_sidebar_problems,
                    "history":  self._build_sidebar_history,
                    "logs":     self._build_sidebar_logs}
        if key in builders:
            builders[key]()
        panels = {"explorer": "_panel_explorer", "problems": "_panel_problems",
                  "history":  "_panel_history",  "logs":     "_panel_logs"}
        for attr in panels.values():
            if hasattr(self, attr):
                getattr(self, attr).pack_forget()
        attr = panels.get(key)
        if attr and hasattr(self, attr):
            getattr(self, attr).pack(fill=tk.BOTH, expand=True)
        if key == "history":
            self._refresh_history_table()

    # ── Right Detail Sidebar ───────────────────────────────────────────────────
    def _build_right_sidebar(self):
        rs = self._right_sidebar

        _SectionLabel(rs, "VULNERABILITY DETAILS").pack(fill=tk.X, padx=0)
        _Separator(rs).pack(fill=tk.X)

        # Summary badges
        badge_row = tk.Frame(rs, bg=C["bg_right"], pady=8)
        badge_row.pack(fill=tk.X, padx=12)

        self._badge_sev = self._make_badge(badge_row, "—", C["fg_muted"])
        self._badge_sev.pack(side=tk.LEFT)
        self._badge_cvss = self._make_badge(badge_row, "CVSS —", C["fg_muted"])
        self._badge_cvss.pack(side=tk.LEFT, padx=6)
        self._badge_conf = self._make_badge(badge_row, "Conf —", C["fg_muted"])
        self._badge_conf.pack(side=tk.LEFT)

        _Separator(rs).pack(fill=tk.X)

        # Scrollable details area
        outer = tk.Frame(rs, bg=C["bg_right"])
        outer.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(outer, bg=C["bg_right"], highlightthickness=0)
        vsb = ttk.Scrollbar(outer, style="Thin.Vertical.TScrollbar", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._detail_frame = tk.Frame(canvas, bg=C["bg_right"])
        self._detail_window = canvas.create_window((0, 0), window=self._detail_frame, anchor="nw")

        def _on_resize(e):
            canvas.itemconfig(self._detail_window, width=e.width)
        canvas.bind("<Configure>", _on_resize)
        self._detail_frame.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<MouseWheel>",
            lambda e: canvas.yview_scroll(-1*(1 if e.delta > 0 else -1), "units"))

        # Build detail sub-sections
        self._detail_rows: Dict[str, tk.Label] = {}
        self._build_detail_section("LOCATION", ["File", "Function", "Lines", "Sink"])
        self._build_detail_section("CLASSIFICATION", ["CWE", "CVE", "CVSS Vector"])
        self._build_detail_section("EVIDENCE", [])
        self._detail_evidence = self._make_detail_textbox(12)
        self._build_detail_section("OWASP RECOMMENDATION", [])
        self._detail_owasp = self._make_detail_textbox(6)
        self._build_detail_section("RAG REFERENCES", [])
        self._detail_refs = self._make_detail_textbox(5)

        self._clear_right_sidebar()

    def _make_badge(self, parent, text, color):
        return tk.Label(parent, text=text, bg=color, fg=C["bg_editor"],
                        font=(C["font_ui"], 8, "bold"), padx=8, pady=2)

    def _build_detail_section(self, title: str, fields: List[str]):
        tk.Label(self._detail_frame, text=title, bg=C["bg_right"], fg=C["fg_muted"],
                 font=(C["font_ui"], 8, "bold"), anchor="w", padx=12, pady=(10,2)
                 ).pack(fill=tk.X)
        for field in fields:
            row = tk.Frame(self._detail_frame, bg=C["bg_right"])
            row.pack(fill=tk.X, padx=12, pady=1)
            tk.Label(row, text=f"{field}:", bg=C["bg_right"], fg=C["fg_muted"],
                     font=(C["font_ui"], 9), width=10, anchor="w").pack(side=tk.LEFT)
            val_lbl = tk.Label(row, text="—", bg=C["bg_right"], fg=C["fg_default"],
                               font=(C["font_mono"], 9), anchor="w", wraplength=180, justify=tk.LEFT)
            val_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self._detail_rows[field] = val_lbl

    def _make_detail_textbox(self, height: int) -> tk.Text:
        t = tk.Text(self._detail_frame, bg=C["bg_editor"], fg=C["fg_default"],
                    font=(C["font_ui"], 9), wrap=tk.WORD, height=height,
                    relief=tk.FLAT, borderwidth=0, padx=12, pady=6, state=tk.DISABLED)
        t.pack(fill=tk.X, padx=4, pady=2)
        t.tag_configure("heading",  foreground=C["fg_accent"], font=(C["font_ui"], 9, "bold"))
        t.tag_configure("green",    foreground=C["fg_green"])
        t.tag_configure("orange",   foreground=C["fg_orange"])
        t.tag_configure("ref",      foreground=C["fg_muted"],  font=(C["font_mono"], 8))
        t.tag_configure("code",     foreground=C["fg_yellow"], font=(C["font_mono"], 9))
        t.tag_configure("red",      foreground=C["fg_red"])
        return t

    def _clear_right_sidebar(self):
        for lbl in self._detail_rows.values():
            lbl.config(text="—", fg=C["fg_muted"])
        self._badge_sev.config(text="—", bg=C["fg_muted"])
        self._badge_cvss.config(text="CVSS —", bg=C["fg_muted"])
        self._badge_conf.config(text="Conf —", bg=C["fg_muted"])
        for tb in (self._detail_evidence, self._detail_owasp, self._detail_refs):
            tb.config(state=tk.NORMAL)
            tb.delete("1.0", tk.END)
            tb.config(state=tk.DISABLED)

    def _populate_right_sidebar(self, finding: Dict[str, Any]):
        sev = finding.get("severity", "—")
        cvss = finding.get("cvss_score", 0)
        conf = finding.get("confidence", 0)
        cwe = finding.get("cwe", "—")
        cve = finding.get("cve", "—")
        sink = finding.get("sink", "—")
        func = finding.get("function_name", "—")
        fpath = finding.get("file_path", "—")
        line = f"{finding.get('start_line','?')}–{finding.get('end_line','?')}"
        vec = finding.get("cvss_vector", "—")

        # Badges
        sev_col = SEV_COLORS.get(sev, C["fg_muted"])
        self._badge_sev.config(text=f"  {sev}  ", bg=sev_col)
        self._badge_cvss.config(text=f"  CVSS {cvss}  ",
                                 bg=(C["sev_critical"] if cvss>=9 else
                                     C["sev_high"] if cvss>=7 else
                                     C["sev_medium"] if cvss>=4 else C["sev_low"]))
        conf_col = (C["fg_red"] if conf>=90 else C["fg_orange"] if conf>=70 else C["fg_muted"])
        self._badge_conf.config(text=f"  {conf}%  ", bg=conf_col)

        # Detail rows
        basename = os.path.basename(fpath)
        self._detail_rows["File"].config(text=basename, fg=C["fg_default"])
        self._detail_rows["Function"].config(text=func, fg=C["fg_yellow"])
        self._detail_rows["Lines"].config(text=line, fg=C["fg_default"])
        self._detail_rows["Sink"].config(text=sink, fg=C["fg_red"])
        self._detail_rows["CWE"].config(text=cwe, fg=C["fg_accent"])
        self._detail_rows["CVE"].config(text=cve, fg=C["fg_orange"])
        self._detail_rows["CVSS Vector"].config(text=vec, fg=C["fg_muted"],
                                                  font=(C["font_mono"], 8))

        # Evidence text
        exp = finding.get("explanation_json", {})
        if isinstance(exp, dict):
            why = exp.get("why", "")
            self._detail_evidence.config(state=tk.NORMAL)
            self._detail_evidence.delete("1.0", tk.END)
            if why:
                self._insert_rich(self._detail_evidence, "Root Cause\n", "heading")
                self._insert_rich(self._detail_evidence, f"{why}\n\n")
                cwe_desc = exp.get("supporting_cwe", "")
                if cwe_desc:
                    self._insert_rich(self._detail_evidence, "CWE\n", "heading")
                    self._insert_rich(self._detail_evidence, f"{cwe_desc}\n")
            else:
                self._detail_evidence.insert(tk.END, "No evidence generated.")
            self._detail_evidence.config(state=tk.DISABLED)

            # OWASP
            owasp = exp.get("owasp_recommendation", "")
            self._detail_owasp.config(state=tk.NORMAL)
            self._detail_owasp.delete("1.0", tk.END)
            self._detail_owasp.insert(tk.END, owasp or "—")
            self._detail_owasp.config(state=tk.DISABLED)

            # References
            refs = exp.get("references", [])
            self._detail_refs.config(state=tk.NORMAL)
            self._detail_refs.delete("1.0", tk.END)
            for r in refs:
                self._insert_rich(self._detail_refs, f"• {r}\n", "ref")
            if not refs:
                self._detail_refs.insert(tk.END, "—")
            self._detail_refs.config(state=tk.DISABLED)

    def _insert_rich(self, widget: tk.Text, text: str, tag: str = ""):
        if tag:
            widget.insert(tk.END, text, tag)
        else:
            widget.insert(tk.END, text)

    # ── Main Editor + Bottom Panel ─────────────────────────────────────────────
    def _build_main_area(self, parent: tk.Frame):
        paned = tk.PanedWindow(parent, orient=tk.VERTICAL, bg=C["border"],
                               sashwidth=4, sashpad=0, handlesize=0)
        paned.pack(fill=tk.BOTH, expand=True)

        # Editor
        editor_outer = tk.Frame(paned, bg=C["bg_editor"])
        paned.add(editor_outer, minsize=200)

        # Tab bar
        tabbar = tk.Frame(editor_outer, bg=C["bg_tab_idle"], height=35)
        tabbar.pack(fill=tk.X)
        tabbar.pack_propagate(False)
        self._editor_tab_lbl = tk.Label(tabbar, text="  Welcome  ",
                                         bg=C["bg_tab_active"], fg=C["fg_default"],
                                         font=(C["font_ui"], 9), padx=12, pady=8)
        self._editor_tab_lbl.pack(side=tk.LEFT)

        # Editor body
        ed_body = tk.Frame(editor_outer, bg=C["bg_editor"])
        ed_body.pack(fill=tk.BOTH, expand=True)
        self.code_text = tk.Text(
            ed_body, bg=C["bg_editor"], fg=C["fg_default"],
            insertbackground=C["cursor"], font=(C["font_mono"], C["font_size"] + 1),
            wrap=tk.NONE, padx=16, pady=8, relief=tk.FLAT, borderwidth=0,
            selectbackground=C["bg_select"], selectforeground=C["fg_title"], undo=True)
        self.code_text.tag_configure("vuln_highlight",
                                      background=C["bg_vuln"], foreground=C["fg_vuln"],
                                      font=(C["font_mono"], C["font_size"] + 1, "bold"))
        ln = _LineNumberCanvas(ed_body, self.code_text)
        ln.pack(side=tk.LEFT, fill=tk.Y)
        self.code_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scy = ttk.Scrollbar(ed_body, style="Thin.Vertical.TScrollbar", command=self.code_text.yview)
        scy.pack(side=tk.RIGHT, fill=tk.Y)
        self.code_text.configure(yscrollcommand=scy.set)
        scx = ttk.Scrollbar(editor_outer, style="Thin.Horizontal.TScrollbar",
                             orient=tk.HORIZONTAL, command=self.code_text.xview)
        scx.pack(fill=tk.X)
        self.code_text.configure(xscrollcommand=scx.set)

        self._show_welcome()

        # Bottom panel
        bottom_outer = tk.Frame(paned, bg=C["bg_sidebar"])
        paned.add(bottom_outer, minsize=140)
        self._build_bottom_panel(bottom_outer)

    def _show_welcome(self):
        msg = ("\n"
               "  Secure Code Forensics IDE\n"
               "  ──────────────────────────────────────────────────\n\n"
               "  ▶  Open Folder    – load any project directory\n"
               "  ▶  Run Scan       – AST + RAG + LLM pipeline\n"
               "  ▶  Apply Patch    – one-click unified diff to disk\n"
               "  ▶  AI Chat        – ask security questions\n\n"
               "  Supported: C, C++, Python, Java, JavaScript, TypeScript\n")
        self.code_text.configure(state=tk.NORMAL)
        self.code_text.delete("1.0", tk.END)
        self.code_text.insert(tk.END, msg)
        self.code_text.configure(state=tk.DISABLED)

    # ── Bottom Panel ───────────────────────────────────────────────────────────
    def _build_bottom_panel(self, parent: tk.Frame):
        tab_bar = tk.Frame(parent, bg=C["bg_sidebar"], height=32)
        tab_bar.pack(fill=tk.X)
        tab_bar.pack_propagate(False)

        self._bottom_tabs: Dict[str, tk.Frame] = {}
        self._bottom_tab_btns: Dict[str, tk.Label] = {}
        self._active_bottom = ""

        for key, label in [("problems","⚠  Problems"), ("evidence","💡  Evidence"),
                            ("patch","🔧  Patch Diff"), ("explain","📄  Explainability"),
                            ("logs_bottom","≡  Logs")]:
            btn = tk.Label(tab_bar, text=f"  {label}  ", bg=C["bg_sidebar"], fg=C["fg_muted"],
                           font=(C["font_ui"], 9), cursor="hand2", padx=4, pady=6)
            btn.pack(side=tk.LEFT)
            btn.bind("<Button-1>", lambda e, k=key: self._switch_bottom_tab(k))
            self._bottom_tab_btns[key] = btn

        _Separator(parent).pack(fill=tk.X)
        content = tk.Frame(parent, bg=C["bg_editor"])
        content.pack(fill=tk.BOTH, expand=True)

        self._build_problems_tab(content)
        self._build_evidence_tab(content)
        self._build_patch_tab(content)
        self._build_explain_tab(content)
        self._build_logs_bottom_tab(content)

        self._switch_bottom_tab("problems")

    def _switch_bottom_tab(self, key: str):
        self._active_bottom = key
        for k, btn in self._bottom_tab_btns.items():
            btn.configure(bg=(C["bg_editor"] if k==key else C["bg_sidebar"]),
                          fg=(C["fg_default"] if k==key else C["fg_muted"]))
        for k, frame in self._bottom_tabs.items():
            if k == key:
                frame.pack(fill=tk.BOTH, expand=True)
            else:
                frame.pack_forget()

    def _build_problems_tab(self, parent):
        frame = tk.Frame(parent, bg=C["bg_editor"])
        self._bottom_tabs["problems"] = frame

        cols = ("severity","confidence","cwe","cve","function","file","line","sink")
        self.problems_table = ttk.Treeview(frame, style="Problems.Treeview",
                                            columns=cols, show="headings")
        headers = [("severity",70,"Severity"),("confidence",65,"Conf %"),
                   ("cwe",110,"CWE"),("cve",110,"CVE"),("function",130,"Function"),
                   ("file",220,"File"),("line",60,"Lines"),("sink",90,"Sink")]
        for col, w, txt in headers:
            self.problems_table.heading(col, text=txt, anchor=tk.W)
            self.problems_table.column(col, width=w, anchor=tk.W)

        for sev, col in [("Critical",C["sev_critical"]),("High",C["sev_high"]),
                          ("Medium",C["sev_medium"]),("Low",C["sev_low"])]:
            self.problems_table.tag_configure(sev, foreground=col)

        self.problems_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.problems_table.bind("<<TreeviewSelect>>", self._on_problem_select)
        sb = ttk.Scrollbar(frame, style="Thin.Vertical.TScrollbar", command=self.problems_table.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.problems_table.configure(yscrollcommand=sb.set)

    def _build_evidence_tab(self, parent):
        frame = tk.Frame(parent, bg=C["bg_editor"])
        self._bottom_tabs["evidence"] = frame

        self.evidence_text = tk.Text(
            frame, bg=C["bg_editor"], fg=C["fg_default"],
            font=(C["font_ui"], 9), wrap=tk.WORD, relief=tk.FLAT,
            borderwidth=0, padx=20, pady=12, state=tk.DISABLED)
        self.evidence_text.tag_configure("h1",    foreground=C["fg_accent"],   font=(C["font_ui"],10,"bold"))
        self.evidence_text.tag_configure("h2",    foreground=C["fg_green"],    font=(C["font_ui"],9,"bold"))
        self.evidence_text.tag_configure("body",  foreground=C["fg_default"],  font=(C["font_ui"],9))
        self.evidence_text.tag_configure("code",  foreground=C["fg_yellow"],   font=(C["font_mono"],9))
        self.evidence_text.tag_configure("ref",   foreground=C["fg_muted"],    font=(C["font_mono"],8))
        self.evidence_text.tag_configure("warn",  foreground=C["fg_red"],      font=(C["font_ui"],9,"bold"))
        self.evidence_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(frame, style="Thin.Vertical.TScrollbar", command=self.evidence_text.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.evidence_text.configure(yscrollcommand=sb.set)

    def _build_patch_tab(self, parent):
        frame = tk.Frame(parent, bg=C["bg_editor"])
        self._bottom_tabs["patch"] = frame

        action_bar = tk.Frame(frame, bg=C["bg_sidebar"], pady=5)
        action_bar.pack(fill=tk.X)
        self.apply_patch_btn = tk.Button(
            action_bar, text="  ✅ Apply Patch to File  ",
            bg=C["fg_accent"], fg=C["bg_editor"], relief=tk.FLAT,
            font=(C["font_ui"], 9, "bold"), cursor="hand2",
            state=tk.DISABLED, command=self._apply_active_patch, padx=8)
        self.apply_patch_btn.pack(side=tk.LEFT, padx=12, pady=2)
        self.patch_status_lbl = tk.Label(action_bar, text="Select a problem to preview patch",
                                          bg=C["bg_sidebar"], fg=C["fg_muted"],
                                          font=(C["font_ui"], 9, "italic"))
        self.patch_status_lbl.pack(side=tk.LEFT)
        _Separator(frame).pack(fill=tk.X)

        diff_frame = tk.Frame(frame, bg=C["bg_editor"])
        diff_frame.pack(fill=tk.BOTH, expand=True)
        self.patch_diff_text = tk.Text(
            diff_frame, bg=C["bg_editor"], fg=C["fg_default"],
            font=(C["font_mono"], 9), wrap=tk.NONE, relief=tk.FLAT,
            borderwidth=0, padx=16, pady=8, state=tk.DISABLED)
        self.patch_diff_text.tag_configure("added",   foreground="#4ec9b0", background="#0f2d22")
        self.patch_diff_text.tag_configure("removed", foreground=C["sev_critical"], background="#2d1515")
        self.patch_diff_text.tag_configure("meta",    foreground=C["fg_muted"])
        self.patch_diff_text.tag_configure("hunk",    foreground="#569cd6")
        self.patch_diff_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(diff_frame, style="Thin.Vertical.TScrollbar", command=self.patch_diff_text.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.patch_diff_text.configure(yscrollcommand=sb.set)

    def _build_explain_tab(self, parent):
        frame = tk.Frame(parent, bg=C["bg_editor"])
        self._bottom_tabs["explain"] = frame

        self.explain_text = tk.Text(
            frame, bg=C["bg_editor"], fg=C["fg_default"],
            font=(C["font_ui"], 9), wrap=tk.WORD, relief=tk.FLAT,
            borderwidth=0, padx=20, pady=12, state=tk.DISABLED)
        self.explain_text.tag_configure("h1",   foreground=C["fg_accent"],  font=(C["font_ui"],10,"bold"))
        self.explain_text.tag_configure("body",  foreground=C["fg_default"], font=(C["font_ui"],9))
        self.explain_text.tag_configure("code",  foreground=C["fg_yellow"],  font=(C["font_mono"],9))
        self.explain_text.tag_configure("muted", foreground=C["fg_muted"],   font=(C["font_ui"],9,"italic"))
        self.explain_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(frame, style="Thin.Vertical.TScrollbar", command=self.explain_text.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.explain_text.configure(yscrollcommand=sb.set)

    def _build_logs_bottom_tab(self, parent):
        frame = tk.Frame(parent, bg=C["bg_editor"])
        self._bottom_tabs["logs_bottom"] = frame
        self._logs_bottom = tk.Text(
            frame, bg=C["bg_editor"], fg=C["fg_muted"],
            font=(C["font_mono"], 9), wrap=tk.WORD, relief=tk.FLAT,
            borderwidth=0, padx=16, pady=8, state=tk.DISABLED)
        self._logs_bottom.tag_configure("ERROR",   foreground=C["sev_critical"])
        self._logs_bottom.tag_configure("WARNING", foreground=C["sev_medium"])
        self._logs_bottom.tag_configure("INFO",    foreground=C["fg_green"])
        self._logs_bottom.tag_configure("STAGE",   foreground=C["fg_accent"])
        self._logs_bottom.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(frame, style="Thin.Vertical.TScrollbar", command=self._logs_bottom.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._logs_bottom.configure(yscrollcommand=sb.set)

    # ── Status Bar ─────────────────────────────────────────────────────────────
    def _build_statusbar(self):
        bar = tk.Frame(self, bg=C["bg_statusbar"], height=22)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)
        self._status_lbl = tk.Label(bar, text="  Ready  |  AST + RAG + LoRA Engine",
                                     bg=C["bg_statusbar"], fg=C["fg_title"],
                                     font=(C["font_ui"], 8), anchor="w")
        self._status_lbl.pack(side=tk.LEFT, padx=4)
        self._status_right = tk.Label(bar, text="UTF-8  ",
                                       bg=C["bg_statusbar"], fg=C["fg_title"],
                                       font=(C["font_ui"], 8), anchor="e")
        self._status_right.pack(side=tk.RIGHT)

    def _set_status(self, text: str, right: str = ""):
        self._status_lbl.configure(text=f"  {text}")
        if right:
            self._status_right.configure(text=f"{right}  ")

    # ── Actions ────────────────────────────────────────────────────────────────
    def _open_project_folder(self):
        folder = filedialog.askdirectory(title="Select Project Folder")
        if not folder:
            return
        self.current_project_folder = os.path.abspath(folder)
        short = os.path.basename(self.current_project_folder)
        self._folder_lbl.configure(text=short)
        self.current_project_id = self.persistence.register_or_get_project(self.current_project_folder)
        self._populate_file_tree(self.current_project_folder)
        self._log("Opened: " + self.current_project_folder, "INFO")
        self._set_status(f"Project: {self.current_project_folder}", short)
        self._switch_panel("explorer")

    def _populate_file_tree(self, root_path: str):
        self.file_tree.delete(*self.file_tree.get_children())
        node_map: Dict[str, str] = {"": ""}
        for root, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if not self.config_mgr.is_ignored_dir(d)]
            rel = os.path.relpath(root, root_path)
            parent_id = ""
            if rel != ".":
                parent_key = os.path.dirname(rel) if os.path.dirname(rel) else ""
                parent_id = node_map.get(parent_key, "")
                dir_id = self.file_tree.insert(parent_id, "end",
                                                text=f"  {os.path.basename(root)}", open=True)
                node_map[rel] = dir_id
            dir_id = node_map.get(rel, "")
            for fname in sorted(files):
                ext = os.path.splitext(fname)[1].lower()
                if self.config_mgr.is_supported_extension(ext):
                    full_f = os.path.join(root, fname)
                    badge = self.file_badges.get(full_f, "")
                    self.file_tree.insert(dir_id, "end", text=f"  {fname}",
                                          values=(badge,), tags=(full_f,))

    # ── Scan Pipeline ──────────────────────────────────────────────────────────
    def _start_scan_thread(self):
        if not self.current_project_folder:
            messagebox.showwarning("No Project", "Open a project folder first.")
            return
        if self.is_scanning:
            return
        self.is_scanning = True
        self._btn_scan.set_enabled(False)
        self._btn_scan.config(text="  ⏳  Scanning…  ")
        self._set_status("Scanning…")

        self._progress_win = ScanProgressWindow(self)
        threading.Thread(target=self._run_scan_pipeline, daemon=True).start()

    def _stage(self, key: str, status: str = "running", detail: str = ""):
        """Update progress window from background thread."""
        self.after(0, lambda: self._progress_win.set_stage(key, status, detail))

    def _run_scan_pipeline(self):
        import time
        try:
            start_t = time.time()
            force_reparse = not self.incremental_var.get()
            self._log(f"Scan started (incremental={not force_reparse})", "STAGE")

            # ── Parse ──────────────────────────────────────────────────────
            self._stage("parse", "running")
            parser_res = self.parser_module.scan_project(self.current_project_folder,
                                                          force_reparse=force_reparse)
            file_results = parser_res.get("file_results", {})
            scanned = parser_res.get("files_scanned", 0)
            cached = parser_res.get("files_from_cache", 0)
            self._stage("parse", "done", f"{scanned} files ({cached} cached)")
            self._log(f"Parser: {scanned} files scanned, {cached} from cache", "INFO")

            self.current_scan_id = self.persistence.create_scan_run(
                self.current_project_id or 1, scanned, 0)

            all_findings: List[Dict[str, Any]] = []
            self.file_badges.clear()

            # ── Correlate ──────────────────────────────────────────────────
            self._stage("correlate", "running")
            for fpath, analysis in file_results.items():
                lang = analysis.get("language", "unknown")
                correlated = self.correlation_module.correlate_file_findings(fpath, lang, analysis)
                analysis["_correlated"] = correlated
            total_corr = sum(len(a.get("_correlated", [])) for a in file_results.values())
            self._stage("correlate", "done", f"{total_corr} candidates")
            self._log(f"Correlation: {total_corr} candidates found", "INFO")

            # ── LLM Verify ─────────────────────────────────────────────────
            llm_online = self.llm_engine.check_connection().get("status") == "ONLINE"
            if llm_online:
                self._stage("llm", "running")
                self._log("LLM online — running verification", "INFO")
            else:
                self._stage("llm", "skip", "offline")
                self._log("LLM offline — skipping inference", "WARNING")

            # ── Verify + Patch + Explain ───────────────────────────────────
            self._stage("verify", "running")
            self._stage("patch", "running")
            self._stage("explain", "running")

            for fpath, analysis in file_results.items():
                lang = analysis.get("language", "unknown")
                file_count = 0
                for corr in analysis.get("_correlated", []):
                    llm_resp: Dict[str, Any] = {}
                    if llm_online:
                        try:
                            prompt = self.prompt_builder.build_verification_prompt(
                                corr, corr.get("rag_context", {}), lang)
                            llm_resp = self.llm_engine.execute_inference(prompt)
                        except Exception:
                            pass

                    verified = self.verification_module.verify_finding(corr, llm_resp)
                    if verified.get("severity") != "Info" and verified.get("confidence", 0) >= 40:
                        patch_info = self.patch_module.generate_patch_for_finding(verified)
                        verified["patch_diff"] = patch_info.get("unified_diff", "")
                        verified["patched_snippet"] = patch_info.get("patched_snippet", "")
                        verified["explanation_json"] = (
                            self.explainability_module.generate_evidence_explanation(verified))
                        all_findings.append(verified)
                        file_count += 1

                if file_count > 0:
                    self.file_badges[fpath] = f"● {file_count}"

            if llm_online:
                self._stage("llm", "done")
            self._stage("verify",  "done", f"{len(all_findings)} findings verified")
            self._stage("patch",   "done")
            self._stage("explain", "done")

            # ── Persist ────────────────────────────────────────────────────
            self._stage("persist", "running")
            self.persistence.save_vulnerabilities(self.current_scan_id, all_findings)
            self.persistence.update_scan_findings_count(self.current_scan_id, len(all_findings))
            self._stage("persist", "done", f"{len(all_findings)} records written")
            self._log(f"Persistence: {len(all_findings)} records saved", "INFO")

            self.vulnerabilities_list = sorted(
                all_findings,
                key=lambda x: (x.get("cvss_score", 0), x.get("confidence", 0)),
                reverse=True)

            elapsed = round(time.time() - start_t, 3)
            msg = (f"Scan done in {elapsed}s  |  "
                   f"{scanned} files  ({cached} cached)  |  "
                   f"{len(self.vulnerabilities_list)} findings")
            self._log(msg, "INFO")
            self.persistence.log_scan_message(self.current_scan_id, msg)

            self._stage("done", "done", msg)
            self.after(10, lambda: self._on_scan_completed(msg))
        except Exception as exc:
            self.after(10, lambda: self._on_scan_error(str(exc)))

    def _on_scan_completed(self, msg: str):
        self.is_scanning = False
        self._btn_scan.config(text="  ▶  Run Scan  ")
        self._btn_scan.set_enabled(True)
        self._set_status(msg)
        self._populate_file_tree(self.current_project_folder)
        self._refresh_problems_table()
        self._refresh_history_table()
        self._switch_bottom_tab("problems")
        if hasattr(self, "_progress_win") and self._progress_win.winfo_exists():
            self._progress_win.finish(msg)
            self.after(2500, lambda: self._progress_win.destroy()
                       if self._progress_win.winfo_exists() else None)

    def _on_scan_error(self, err: str):
        self.is_scanning = False
        self._btn_scan.config(text="  ▶  Run Scan  ")
        self._btn_scan.set_enabled(True)
        self._set_status(f"Error: {err}")
        self._log(f"Scan FAILED: {err}", "ERROR")
        if hasattr(self, "_progress_win") and self._progress_win.winfo_exists():
            self._progress_win.set_stage("done", "error", err[:60])
        messagebox.showerror("Scan Error", err)

    # ── Table Refresh ──────────────────────────────────────────────────────────
    def _refresh_problems_table(self):
        self.problems_table.delete(*self.problems_table.get_children())
        if hasattr(self, "_problems_list"):
            self._problems_list.delete(0, tk.END)

        for idx, item in enumerate(self.vulnerabilities_list):
            sev = item.get("severity", "High")
            conf = item.get("confidence", 65)
            cwe = item.get("cwe", "—")
            cve = item.get("cve", "—")
            func = item.get("function_name", "—")
            fpath = (os.path.relpath(item.get("file_path", ""), self.current_project_folder)
                     if self.current_project_folder else item.get("file_path", ""))
            lines = f"{item.get('start_line','?')}–{item.get('end_line','?')}"
            sink = item.get("sink", "—")

            self.problems_table.insert("", "end", iid=str(idx),
                values=(sev, f"{conf}%", cwe, cve, func, fpath, lines, sink),
                tags=(sev,))

            if hasattr(self, "_problems_list"):
                icon = ("⬤" if sev == "Critical" else "▲" if sev == "High" else "▸")
                self._problems_list.insert(
                    tk.END, f"  {icon}  [{sev}]  {os.path.basename(fpath)}:{item.get('start_line','?')}")

    def _refresh_history_table(self):
        if not hasattr(self, "history_table"):
            return
        self.history_table.delete(*self.history_table.get_children())
        history = self.persistence.list_scan_history(self.current_project_id)
        for h in history:
            ts = h.get("timestamp", "")[:19].replace("T", " ")
            self.history_table.insert("", "end",
                values=(h.get("id"), ts, h.get("file_count", 0), h.get("findings_count", 0)))

    # ── Selection Handlers ─────────────────────────────────────────────────────
    def _on_file_tree_select(self, _=None):
        sel = self.file_tree.selection()
        if not sel:
            return
        tags = self.file_tree.item(sel[0], "tags")
        if tags and os.path.isfile(str(tags[0])):
            self._display_file_in_editor(str(tags[0]))

    def _on_sidebar_problem_click(self, _=None):
        if not hasattr(self, "_problems_list"):
            return
        sel = self._problems_list.curselection()
        if sel:
            self._select_finding(sel[0])

    def _on_problem_select(self, _=None):
        sel = self.problems_table.selection()
        if sel:
            self._select_finding(int(sel[0]))

    def _select_finding(self, idx: int):
        if not (0 <= idx < len(self.vulnerabilities_list)):
            return
        item = self.vulnerabilities_list[idx]
        self.active_finding = item

        # Open file in editor
        fpath = item.get("file_path", "")
        if os.path.exists(fpath):
            self._display_file_in_editor(fpath, highlight_line=item.get("start_line", 1))

        # Populate right sidebar
        self._populate_right_sidebar(item)

        # Evidence tab — rich formatted
        self._render_evidence(item)

        # Explainability tab — full markdown
        self._render_explainability(item)

        # Patch diff tab
        self._render_patch(item)

    def _display_file_in_editor(self, file_path: str, highlight_line: Optional[int] = None):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            self.active_file_path = file_path
            fname = os.path.basename(file_path)
            self._editor_tab_lbl.configure(text=f"  {fname}  ")
            ext = os.path.splitext(file_path)[1].lstrip(".")
            self._status_right.configure(text=f"{ext.upper() or 'Text'} · UTF-8  ")

            self.code_text.configure(state=tk.NORMAL)
            self.code_text.delete("1.0", tk.END)
            self.code_text.insert(tk.END, content)

            if highlight_line and highlight_line > 0:
                self.code_text.tag_remove("vuln_highlight", "1.0", tk.END)
                self.code_text.tag_add("vuln_highlight",
                                        f"{highlight_line}.0", f"{highlight_line}.end")
                self.code_text.see(f"{max(1, highlight_line - 4)}.0")
        except Exception as exc:
            self._log(f"Cannot read {file_path}: {exc}", "WARNING")

    def _render_evidence(self, item: Dict[str, Any]):
        exp = item.get("explanation_json", {})
        t = self.evidence_text
        t.configure(state=tk.NORMAL)
        t.delete("1.0", tk.END)

        if not isinstance(exp, dict) or not exp:
            t.insert(tk.END, "No evidence generated for this finding.\n", "muted")
            t.configure(state=tk.DISABLED)
            return

        # Root Cause
        why = exp.get("why", "")
        if why:
            t.insert(tk.END, "⬤ Root Cause Analysis\n", "h1")
            t.insert(tk.END, f"{why}\n\n", "body")

        # CWE
        cwe_desc = exp.get("supporting_cwe", "")
        if cwe_desc:
            t.insert(tk.END, "⬤ CWE Classification\n", "h1")
            t.insert(tk.END, f"{cwe_desc}\n\n", "body")

        # CVE
        cve_desc = exp.get("supporting_cve", "")
        if cve_desc:
            t.insert(tk.END, "⬤ CVE Reference\n", "h1")
            t.insert(tk.END, f"{cve_desc}\n\n", "body")

        # Example
        example = exp.get("primevul_example", "")
        if example:
            t.insert(tk.END, "⬤ Vulnerable Code Pattern\n", "h1")
            t.insert(tk.END, f"{example}\n\n", "code")

        # OWASP
        owasp = exp.get("owasp_recommendation", "")
        if owasp:
            t.insert(tk.END, "⬤ OWASP Remediation\n", "h1")
            t.insert(tk.END, f"{owasp}\n\n", "body")

        # References
        refs = exp.get("references", [])
        if refs:
            t.insert(tk.END, "⬤ RAG Retrieved References\n", "h1")
            for r in refs:
                t.insert(tk.END, f"  • {r}\n", "ref")

        t.configure(state=tk.DISABLED)

    def _render_explainability(self, item: Dict[str, Any]):
        exp = item.get("explanation_json", {})
        t = self.explain_text
        t.configure(state=tk.NORMAL)
        t.delete("1.0", tk.END)

        if isinstance(exp, dict) and exp.get("markdown_report"):
            md = exp["markdown_report"]
            # Render markdown-ish: lines starting with ### get h1 tag
            for line in md.split("\n"):
                if line.startswith("### "):
                    t.insert(tk.END, f"{line[4:]}\n", "h1")
                elif line.startswith("```"):
                    pass  # skip fence markers
                else:
                    t.insert(tk.END, f"{line}\n", "body")
        else:
            sev = item.get("severity", "?")
            cwe = item.get("cwe", "?")
            func = item.get("function_name", "?")
            score = item.get("cvss_score", 0)
            conf = item.get("confidence", 0)
            t.insert(tk.END, "Root Cause\n", "h1")
            t.insert(tk.END,
                f"{item.get('sink', '?')} vulnerability in {func}\n\n"
                f"Severity: {sev}  CWE: {cwe}  CVSS: {score}  Confidence: {conf}%\n",
                "body")
        t.configure(state=tk.DISABLED)

    def _render_patch(self, item: Dict[str, Any]):
        diff_text = item.get("patch_diff", "")
        fpath = item.get("file_path", "")

        t = self.patch_diff_text
        t.configure(state=tk.NORMAL)
        t.delete("1.0", tk.END)

        if diff_text:
            for line in diff_text.splitlines(keepends=True):
                if line.startswith("+") and not line.startswith("+++"):
                    t.insert(tk.END, line, "added")
                elif line.startswith("-") and not line.startswith("---"):
                    t.insert(tk.END, line, "removed")
                elif line.startswith("@@"):
                    t.insert(tk.END, line, "hunk")
                elif line.startswith("---") or line.startswith("+++"):
                    t.insert(tk.END, line, "meta")
                else:
                    t.insert(tk.END, line)
            self.apply_patch_btn.configure(state=tk.NORMAL)
            self.patch_status_lbl.configure(
                text=f"Fix ready for {item.get('cwe','?')} in {os.path.basename(fpath)}")
        else:
            t.insert(tk.END, "  // No automated patch generated for this finding.\n", "meta")
            t.insert(tk.END,
                "  // Ensure LLM is online for AI-suggested patches, "
                "or add the sink to heuristic rules in patch_generation.py", "meta")
            self.apply_patch_btn.configure(state=tk.DISABLED)
        t.configure(state=tk.DISABLED)

    def _on_history_double_click(self, _=None):
        if not hasattr(self, "history_table"):
            return
        sel = self.history_table.selection()
        if not sel:
            return
        vals = self.history_table.item(sel[0], "values")
        if vals:
            scan_id = int(vals[0])
            loaded = self.persistence.get_scan_vulnerabilities(scan_id)
            self.vulnerabilities_list = loaded
            self._refresh_problems_table()
            self._switch_bottom_tab("problems")
            self._log(f"Loaded {len(loaded)} findings from scan #{scan_id}", "INFO")

    def _apply_active_patch(self):
        if not self.active_finding or not self.active_finding.get("patched_snippet"):
            return
        fpath = self.active_finding.get("file_path", "")
        if not os.path.exists(fpath):
            messagebox.showerror("Error", f"File not found: {fpath}")
            return
        orig = self.active_finding.get("correlated_item", {}).get("full_snippet", "")
        patched = self.active_finding.get("patched_snippet", "")
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
            if orig and orig in content:
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(content.replace(orig, patched, 1))
                messagebox.showinfo("Patch Applied", f"Patch applied to:\n{fpath}")
                self._display_file_in_editor(fpath, self.active_finding.get("start_line", 1))
                self._log(f"Patch applied: {fpath}", "INFO")
            else:
                messagebox.showwarning("Alignment",
                    "Original snippet not found in file. Review the diff manually.")
        except Exception as exc:
            messagebox.showerror("Write Error", str(exc))

    # ── Chat ───────────────────────────────────────────────────────────────────
    # Chat is accessed via AI Chat activity panel
    def _send_chat_question(self):
        if not hasattr(self, "_chat_entry"):
            return
        question = self._chat_entry.get().strip()
        if not question:
            return
        self._chat_entry.delete(0, tk.END)
        self._chat_display.configure(state=tk.NORMAL)
        self._chat_display.insert(tk.END, f"\nYou\n  {question}\n", "user_tag")
        self._chat_display.see(tk.END)
        self._chat_display.configure(state=tk.DISABLED)

        code_ctx = (self.code_text.get("1.0", tk.END)[:1500]
                    if self.active_file_path else "No file opened.")
        rag_ctx = (self.active_finding.get("correlated_item", {}).get("rag_context", {})
                   if self.active_finding else {})

        conn = self.llm_engine.check_connection()
        if conn.get("status") != "ONLINE":
            self._chat_display.configure(state=tk.NORMAL)
            self._chat_display.insert(tk.END,
                f"\nAssistant\n  LLM offline ({conn.get('provider','?')}).\n"
                "  Start Ollama or configure endpoint in Settings.\n", "err_tag")
            self._chat_display.see(tk.END)
            self._chat_display.configure(state=tk.DISABLED)
            return

        def run_chat():
            try:
                prompt = self.prompt_builder.build_chat_prompt(question, code_ctx, "c", rag_ctx)
                self._chat_display.configure(state=tk.NORMAL)
                self._chat_display.insert(tk.END, "\nAssistant\n  ", "ai_tag")
                for token in self.llm_engine.stream_chat(prompt):
                    self._chat_display.insert(tk.END, token)
                    self._chat_display.see(tk.END)
                self._chat_display.insert(tk.END, "\n")
                self._chat_display.see(tk.END)
                self._chat_display.configure(state=tk.DISABLED)
                if self.current_project_id:
                    self.persistence.save_chat_message(
                        self.current_project_id, question, "", {"file": self.active_file_path})
            except LLMBackendOfflineError as exc:
                self._chat_display.configure(state=tk.NORMAL)
                self._chat_display.insert(tk.END, f"\n[Error]: {exc}\n", "err_tag")
                self._chat_display.see(tk.END)
                self._chat_display.configure(state=tk.DISABLED)

        threading.Thread(target=run_chat, daemon=True).start()

    # ── Settings ───────────────────────────────────────────────────────────────
    def _open_settings_dialog(self):
        win = tk.Toplevel(self)
        win.title("Settings")
        win.geometry("520x380")
        win.configure(bg=C["bg_sidebar"])
        win.resizable(False, False)

        tk.Label(win, text="  Settings", bg=C["bg_titlebar"], fg=C["fg_title"],
                 font=(C["font_ui"], 11, "bold"), anchor="w", pady=10).pack(fill=tk.X)

        def _lbl(t):
            tk.Label(win, text=t, bg=C["bg_sidebar"], fg=C["fg_muted"],
                     font=(C["font_ui"], 9, "bold"), anchor="w").pack(
                fill=tk.X, padx=20, pady=(14, 2))

        def _entry(var):
            e = tk.Entry(win, textvariable=var, bg=C["bg_input"], fg=C["fg_default"],
                         insertbackground=C["cursor"], relief=tk.FLAT, font=(C["font_mono"], 9))
            e.pack(fill=tk.X, padx=20)

        _lbl("LLM Provider")
        provider_var = tk.StringVar(value=self.config_mgr.get("llm_provider", "ollama"))
        ttk.Combobox(win, textvariable=provider_var,
                     values=["ollama", "openai_compatible", "huggingface_lora"]
                     ).pack(fill=tk.X, padx=20)

        _lbl("LLM Endpoint URL")
        endpoint_var = tk.StringVar(value=self.config_mgr.get(
            "llm_endpoint", "http://localhost:11434/api/chat"))
        _entry(endpoint_var)

        _lbl("Model Name / LoRA Path")
        model_var = tk.StringVar(value=self.config_mgr.get("llm_model", "deepseek-coder:6.7b"))
        _entry(model_var)

        def _save():
            self.config_mgr.set("llm_provider", provider_var.get())
            self.config_mgr.set("llm_endpoint", endpoint_var.get())
            self.config_mgr.set("llm_model", model_var.get())
            self.config_mgr.save()
            self._log(f"Settings saved: provider={provider_var.get()}", "INFO")
            win.destroy()

        tk.Button(win, text="  Save  ", bg=C["fg_accent"], fg=C["bg_editor"],
                  font=(C["font_ui"], 9, "bold"), relief=tk.FLAT,
                  cursor="hand2", command=_save, padx=16).pack(pady=20)

    # ── Logging ────────────────────────────────────────────────────────────────
    def _log(self, msg: str, level: str = "INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        full = f"[{ts}] [{level}] {msg}\n"
        for widget in (
            getattr(self, "logs_text", None),
            getattr(self, "_logs_bottom", None),
        ):
            if widget is None:
                continue
            try:
                widget.configure(state=tk.NORMAL)
                widget.insert(tk.END, f"[{ts}] ", "INFO")
                widget.insert(tk.END, f"[{level}] ", level)
                widget.insert(tk.END, f"{msg}\n")
                widget.see(tk.END)
                widget.configure(state=tk.DISABLED)
            except Exception:
                pass
