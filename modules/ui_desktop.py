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


# ──────────────────────────────────────────────────────────────────────────────
#  VS Code-inspired Design Tokens
# ──────────────────────────────────────────────────────────────────────────────
C = {
    # backgrounds
    "bg_editor":     "#1e1e1e",   # editor background
    "bg_sidebar":    "#252526",   # sidebar / panel bg
    "bg_activity":   "#333333",   # activity bar (far left strip)
    "bg_tab_active": "#1e1e1e",   # active tab matches editor
    "bg_tab_idle":   "#2d2d2d",   # inactive tab
    "bg_titlebar":   "#3c3c3c",   # title bar
    "bg_statusbar":  "#007acc",   # VS Code blue status bar
    "bg_input":      "#3c3c3c",   # input / entry bg
    "bg_hover":      "#2a2d2e",   # hover state
    "bg_select":     "#094771",   # selection highlight
    "bg_vuln":       "#3a1515",   # vulnerable line highlight
    "bg_vuln_gutter":"#5a1010",   # gutter highlight for vuln lines
    # foregrounds
    "fg_default":    "#d4d4d4",   # default text
    "fg_muted":      "#858585",   # muted / secondary text
    "fg_title":      "#ffffff",   # titles / bright
    "fg_accent":     "#569cd6",   # VS Code blue accent
    "fg_green":      "#4ec9b0",   # teal / info
    "fg_yellow":     "#dcdcaa",   # yellow
    "fg_orange":     "#ce9178",   # orange strings
    "fg_red":        "#f44747",   # errors / critical
    "fg_vuln":       "#ff6b6b",   # vulnerable code
    # severity colours
    "sev_critical":  "#f44747",
    "sev_high":      "#d78700",
    "sev_medium":    "#dcdcaa",
    "sev_low":       "#4ec9b0",
    # misc
    "border":        "#454545",
    "cursor":        "#aeafad",
    "font_mono":     "Consolas",
    "font_ui":       "Segoe UI",
    "font_size":     10,
}


class _LineNumberCanvas(tk.Canvas):
    """Draws line numbers alongside a tk.Text widget."""

    def __init__(self, master, text_widget: tk.Text, **kw):
        super().__init__(
            master,
            width=52,
            bg=C["bg_sidebar"],
            highlightthickness=0,
            **kw,
        )
        self._text = text_widget
        self._text.bind("<Configure>", self._on_change)
        self._text.bind("<KeyRelease>", self._on_change)
        self._text.bind("<<Modified>>", self._on_change)
        self._text.bind("<MouseWheel>", self._on_change)

    def _on_change(self, event=None):
        self.after_idle(self._redraw)

    def _redraw(self):
        self.delete("all")
        i = self._text.index("@0,0")
        while True:
            bbox = self._text.dlineinfo(i)
            if bbox is None:
                break
            y = bbox[1]
            lineno = str(i).split(".")[0]
            self.create_text(
                46, y + 1,
                anchor="ne",
                text=lineno,
                fill=C["fg_muted"],
                font=(C["font_mono"], C["font_size"] - 1),
            )
            i = self._text.index(f"{i}+1line")
            if i == self._text.index(f"{i}"):
                break


class _FlatButton(tk.Frame):
    """Flat, borderless icon+label button that matches VS Code toolbar style."""

    def __init__(self, master, text: str, command=None, icon: str = "", accent: bool = False, **kw):
        super().__init__(master, bg=C["bg_titlebar"], **kw)
        self._cmd = command
        self._accent = accent

        fg = C["fg_accent"] if accent else C["fg_default"]
        self._lbl = tk.Label(
            self,
            text=f"  {icon}  {text}  " if icon else f"  {text}  ",
            bg=C["bg_titlebar"],
            fg=fg,
            font=(C["font_ui"], C["font_size"]),
            cursor="hand2",
            padx=6, pady=4,
        )
        self._lbl.pack()

        for w in (self, self._lbl):
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)
            w.bind("<Button-1>", self._on_click)

    def _on_enter(self, _=None):
        self._lbl.configure(bg="#505050")
        self.configure(bg="#505050")

    def _on_leave(self, _=None):
        bg = C["bg_titlebar"]
        self._lbl.configure(bg=bg)
        self.configure(bg=bg)

    def _on_click(self, _=None):
        if self._cmd:
            self._cmd()

    def configure_state(self, enabled: bool):
        if enabled:
            self._lbl.configure(fg=C["fg_accent"] if self._accent else C["fg_default"], cursor="hand2")
        else:
            self._lbl.configure(fg=C["fg_muted"], cursor="")


class _ActivityButton(tk.Label):
    """Side-bar activity bar icon button."""

    def __init__(self, master, icon: str, tooltip: str, command=None, **kw):
        super().__init__(
            master,
            text=icon,
            bg=C["bg_activity"],
            fg=C["fg_muted"],
            font=(C["font_ui"], 16),
            cursor="hand2",
            width=2,
            pady=10,
            **kw,
        )
        self._cmd = command
        self._tooltip = tooltip
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)

    def _on_enter(self, _=None):
        self.configure(fg=C["fg_title"])

    def _on_leave(self, _=None):
        self.configure(fg=C["fg_muted"])

    def _on_click(self, _=None):
        if self._cmd:
            self._cmd()

    def set_active(self, active: bool):
        self.configure(fg=C["fg_title"] if active else C["fg_muted"])


# ──────────────────────────────────────────────────────────────────────────────
#  Main IDE Window
# ──────────────────────────────────────────────────────────────────────────────
class SecureCodeForensicsIDE(tk.Tk):
    """VS Code-style Secure Code Forensics IDE."""

    def __init__(self):
        super().__init__()
        self.title("Forensics IDE")
        self.geometry("1600x950")
        self.minsize(1100, 650)
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
        self._active_panel = "explorer"  # activity bar state

        self._apply_styles()
        self._build_ui()
        self._refresh_history_table()

    # ── Styles ─────────────────────────────────────────────────────────────────
    def _apply_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # Base
        style.configure(".",
            background=C["bg_editor"],
            foreground=C["fg_default"],
            font=(C["font_ui"], C["font_size"]),
            borderwidth=0,
        )
        style.configure("TFrame", background=C["bg_editor"])
        style.configure("Sidebar.TFrame", background=C["bg_sidebar"])
        style.configure("Activity.TFrame", background=C["bg_activity"])
        style.configure("TLabel", background=C["bg_editor"], foreground=C["fg_default"])
        style.configure("Sidebar.TLabel", background=C["bg_sidebar"], foreground=C["fg_muted"],
                        font=(C["font_ui"], 9))
        style.configure("SidebarTitle.TLabel", background=C["bg_sidebar"], foreground=C["fg_muted"],
                        font=(C["font_ui"], 9, "bold"), padding=(12, 8, 0, 6))
        style.configure("Status.TLabel", background=C["bg_statusbar"], foreground=C["fg_title"],
                        font=(C["font_ui"], 9), padding=(8, 3))

        # Treeview – project explorer
        style.configure("Explorer.Treeview",
            background=C["bg_sidebar"],
            foreground=C["fg_default"],
            fieldbackground=C["bg_sidebar"],
            rowheight=22,
            font=(C["font_ui"], C["font_size"]),
            borderwidth=0,
        )
        style.map("Explorer.Treeview",
            background=[("selected", C["bg_select"])],
            foreground=[("selected", C["fg_title"])],
        )
        style.configure("Explorer.Treeview.Heading",
            background=C["bg_sidebar"],
            foreground=C["fg_muted"],
            font=(C["font_ui"], 8, "bold"),
            borderwidth=0,
        )

        # Treeview – problems table
        style.configure("Problems.Treeview",
            background=C["bg_editor"],
            foreground=C["fg_default"],
            fieldbackground=C["bg_editor"],
            rowheight=24,
            font=(C["font_mono"], 9),
            borderwidth=0,
        )
        style.map("Problems.Treeview",
            background=[("selected", C["bg_select"])],
            foreground=[("selected", C["fg_title"])],
        )
        style.configure("Problems.Treeview.Heading",
            background=C["bg_sidebar"],
            foreground=C["fg_muted"],
            font=(C["font_ui"], 9, "bold"),
            borderwidth=0,
        )

        # Scrollbars – thin, dark
        style.configure("Thin.Vertical.TScrollbar",
            background=C["bg_sidebar"],
            troughcolor=C["bg_editor"],
            arrowcolor=C["bg_sidebar"],
            width=8,
        )
        style.configure("Thin.Horizontal.TScrollbar",
            background=C["bg_sidebar"],
            troughcolor=C["bg_editor"],
            arrowcolor=C["bg_sidebar"],
            width=8,
        )

        # PanedWindow sash
        style.configure("TPanedwindow", background=C["border"])

        # Entry
        style.configure("TEntry",
            fieldbackground=C["bg_input"],
            foreground=C["fg_default"],
            insertcolor=C["cursor"],
            borderwidth=1,
            relief="flat",
        )

        # Combobox
        style.configure("TCombobox",
            fieldbackground=C["bg_input"],
            background=C["bg_input"],
            foreground=C["fg_default"],
            arrowcolor=C["fg_muted"],
        )

        # Checkbutton
        style.configure("TCheckbutton",
            background=C["bg_titlebar"],
            foreground=C["fg_muted"],
            font=(C["font_ui"], 9),
        )
        style.map("TCheckbutton",
            background=[("active", C["bg_titlebar"])],
            foreground=[("active", C["fg_default"])],
        )

    # ── Root Layout ────────────────────────────────────────────────────────────
    def _build_ui(self):
        # Title bar (toolbar)
        self._build_titlebar()

        # Body: activity-bar | sidebar | editor
        body = tk.Frame(self, bg=C["bg_editor"])
        body.pack(fill=tk.BOTH, expand=True)

        # Activity bar (far left narrow strip)
        self._activity_bar = tk.Frame(body, bg=C["bg_activity"], width=48)
        self._activity_bar.pack(side=tk.LEFT, fill=tk.Y)
        self._activity_bar.pack_propagate(False)
        self._build_activity_bar()

        # 1px separator
        tk.Frame(body, bg=C["border"], width=1).pack(side=tk.LEFT, fill=tk.Y)

        # Sidebar
        self._sidebar_frame = tk.Frame(body, bg=C["bg_sidebar"], width=280)
        self._sidebar_frame.pack(side=tk.LEFT, fill=tk.Y)
        self._sidebar_frame.pack_propagate(False)

        # 1px separator
        tk.Frame(body, bg=C["border"], width=1).pack(side=tk.LEFT, fill=tk.Y)

        # Main area (editor + bottom panel)
        main_area = tk.Frame(body, bg=C["bg_editor"])
        main_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._build_sidebar_explorer()
        self._build_main_area(main_area)
        self._build_statusbar()

    # ── Title Bar / Toolbar ────────────────────────────────────────────────────
    def _build_titlebar(self):
        bar = tk.Frame(self, bg=C["bg_titlebar"], height=36)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)

        # App icon + name
        tk.Label(
            bar,
            text="  🛡  Forensics IDE",
            bg=C["bg_titlebar"],
            fg=C["fg_default"],
            font=(C["font_ui"], 10, "bold"),
        ).pack(side=tk.LEFT)

        # Divider
        tk.Frame(bar, bg=C["border"], width=1).pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=6)

        # Buttons
        self._btn_open = _FlatButton(bar, "Open Folder", command=self._open_project_folder, icon="📁")
        self._btn_open.pack(side=tk.LEFT)

        self._btn_scan = _FlatButton(bar, "Run Scan", command=self._start_scan_thread, icon="▶", accent=True)
        self._btn_scan.pack(side=tk.LEFT, padx=2)

        tk.Frame(bar, bg=C["border"], width=1).pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=6)

        self._incr_check = ttk.Checkbutton(
            bar,
            text="Incremental",
            variable=self.incremental_var,
            style="TCheckbutton",
        )
        self._incr_check.pack(side=tk.LEFT, padx=4)

        # Right side
        _FlatButton(bar, "Settings", command=self._open_settings_dialog, icon="⚙").pack(side=tk.RIGHT, padx=2)

        # Current folder label
        self._folder_lbl = tk.Label(
            bar,
            text="No project opened",
            bg=C["bg_titlebar"],
            fg=C["fg_muted"],
            font=(C["font_ui"], 9, "italic"),
        )
        self._folder_lbl.pack(side=tk.LEFT, padx=12)

    # ── Activity Bar ───────────────────────────────────────────────────────────
    def _build_activity_bar(self):
        self._act_btns: Dict[str, _ActivityButton] = {}

        items = [
            ("explorer",  "☰", "Explorer"),
            ("problems",  "⚠", "Problems"),
            ("chat",      "💬", "AI Chat"),
            ("history",   "⏱", "Scan History"),
        ]

        for key, icon, tip in items:
            btn = _ActivityButton(
                self._activity_bar,
                icon=icon,
                tooltip=tip,
                command=lambda k=key: self._switch_panel(k),
            )
            btn.pack(fill=tk.X)
            self._act_btns[key] = btn

        # Logs at the bottom
        tk.Frame(self._activity_bar, bg=C["bg_activity"]).pack(fill=tk.BOTH, expand=True)
        logs_btn = _ActivityButton(
            self._activity_bar,
            icon="≡",
            tooltip="Logs",
            command=lambda: self._switch_panel("logs"),
        )
        logs_btn.pack(fill=tk.X)
        self._act_btns["logs"] = logs_btn

        self._set_active_btn("explorer")

    def _set_active_btn(self, key: str):
        for k, b in self._act_btns.items():
            b.set_active(k == key)
        # Left border indicator
        for child in self._activity_bar.winfo_children():
            child.configure(relief=tk.FLAT)
        if key in self._act_btns:
            self._act_btns[key].configure(relief=tk.FLAT, fg=C["fg_title"])

    # ── Sidebar Panels ─────────────────────────────────────────────────────────
    def _build_sidebar_explorer(self):
        """File explorer panel (default sidebar view)."""
        self._panel_explorer = tk.Frame(self._sidebar_frame, bg=C["bg_sidebar"])

        title = tk.Label(
            self._panel_explorer,
            text="EXPLORER",
            bg=C["bg_sidebar"],
            fg=C["fg_muted"],
            font=(C["font_ui"], 9, "bold"),
            anchor="w",
        )
        title.pack(fill=tk.X, padx=12, pady=(10, 4))

        tree_frame = tk.Frame(self._panel_explorer, bg=C["bg_sidebar"])
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.file_tree = ttk.Treeview(
            tree_frame,
            style="Explorer.Treeview",
            columns=("badge",),
            displaycolumns=("badge",),
            show="tree",
        )
        self.file_tree.column("#0", width=230)
        self.file_tree.column("badge", width=40, anchor=tk.CENTER)
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.file_tree.bind("<<TreeviewSelect>>", self._on_file_tree_select)

        sb = ttk.Scrollbar(tree_frame, style="Thin.Vertical.TScrollbar", command=self.file_tree.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_tree.configure(yscrollcommand=sb.set)

        self._panel_explorer.pack(fill=tk.BOTH, expand=True)

    def _build_sidebar_problems(self):
        """Problems mini-list in the sidebar (clicking switches bottom panel)."""
        if hasattr(self, "_panel_problems"):
            return
        self._panel_problems = tk.Frame(self._sidebar_frame, bg=C["bg_sidebar"])

        tk.Label(
            self._panel_problems,
            text="PROBLEMS",
            bg=C["bg_sidebar"], fg=C["fg_muted"],
            font=(C["font_ui"], 9, "bold"), anchor="w",
        ).pack(fill=tk.X, padx=12, pady=(10, 4))

        self._problems_sidebar_list = tk.Listbox(
            self._panel_problems,
            bg=C["bg_sidebar"],
            fg=C["fg_default"],
            selectbackground=C["bg_select"],
            selectforeground=C["fg_title"],
            font=(C["font_mono"], 9),
            relief=tk.FLAT,
            borderwidth=0,
            activestyle="none",
        )
        self._problems_sidebar_list.pack(fill=tk.BOTH, expand=True, padx=4)
        self._problems_sidebar_list.bind("<<ListboxSelect>>", self._on_sidebar_problem_click)

    def _build_sidebar_chat_panel(self):
        if hasattr(self, "_panel_chat_sidebar"):
            return
        self._panel_chat_sidebar = tk.Frame(self._sidebar_frame, bg=C["bg_sidebar"])
        tk.Label(
            self._panel_chat_sidebar,
            text="AI FORENSICS CHAT",
            bg=C["bg_sidebar"], fg=C["fg_muted"],
            font=(C["font_ui"], 9, "bold"), anchor="w",
        ).pack(fill=tk.X, padx=12, pady=(10, 4))

        self.chat_display = tk.Text(
            self._panel_chat_sidebar,
            bg=C["bg_sidebar"],
            fg=C["fg_default"],
            font=(C["font_ui"], 9),
            wrap=tk.WORD,
            relief=tk.FLAT,
            borderwidth=0,
            padx=10, pady=6,
            state=tk.DISABLED,
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True)

        # Colour tags
        self.chat_display.tag_configure("user_tag", foreground=C["fg_accent"], font=(C["font_ui"], 9, "bold"))
        self.chat_display.tag_configure("ai_tag", foreground=C["fg_green"], font=(C["font_ui"], 9, "bold"))
        self.chat_display.tag_configure("err_tag", foreground=C["fg_red"], font=(C["font_ui"], 9))

        input_frame = tk.Frame(self._panel_chat_sidebar, bg=C["bg_input"], pady=6)
        input_frame.pack(fill=tk.X, padx=6, pady=4)

        self.chat_entry = tk.Entry(
            input_frame,
            bg=C["bg_input"],
            fg=C["fg_default"],
            insertbackground=C["cursor"],
            relief=tk.FLAT,
            font=(C["font_ui"], 9),
        )
        self.chat_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 0))
        self.chat_entry.bind("<Return>", lambda e: self._send_chat_question())

        send_btn = tk.Button(
            input_frame,
            text="▶",
            bg=C["fg_accent"],
            fg=C["bg_editor"],
            relief=tk.FLAT,
            font=(C["font_ui"], 9, "bold"),
            cursor="hand2",
            command=self._send_chat_question,
            padx=8,
        )
        send_btn.pack(side=tk.RIGHT, padx=4)

    def _build_sidebar_history(self):
        if hasattr(self, "_panel_history_sidebar"):
            return
        self._panel_history_sidebar = tk.Frame(self._sidebar_frame, bg=C["bg_sidebar"])
        tk.Label(
            self._panel_history_sidebar,
            text="SCAN HISTORY",
            bg=C["bg_sidebar"], fg=C["fg_muted"],
            font=(C["font_ui"], 9, "bold"), anchor="w",
        ).pack(fill=tk.X, padx=12, pady=(10, 4))

        cols = ("id", "time", "files", "findings")
        self.history_table = ttk.Treeview(
            self._panel_history_sidebar,
            style="Explorer.Treeview",
            columns=cols,
            show="headings",
        )
        for col, w, text in [
            ("id", 40, "ID"), ("time", 120, "Time"), ("files", 50, "Files"), ("findings", 60, "Issues")
        ]:
            self.history_table.heading(col, text=text)
            self.history_table.column(col, width=w, anchor=tk.CENTER)
        self.history_table.pack(fill=tk.BOTH, expand=True, padx=4)
        self.history_table.bind("<Double-1>", self._on_history_double_click)

    def _build_sidebar_logs(self):
        if hasattr(self, "_panel_logs_sidebar"):
            return
        self._panel_logs_sidebar = tk.Frame(self._sidebar_frame, bg=C["bg_sidebar"])
        tk.Label(
            self._panel_logs_sidebar,
            text="OUTPUT",
            bg=C["bg_sidebar"], fg=C["fg_muted"],
            font=(C["font_ui"], 9, "bold"), anchor="w",
        ).pack(fill=tk.X, padx=12, pady=(10, 4))

        self.logs_text = tk.Text(
            self._panel_logs_sidebar,
            bg=C["bg_sidebar"],
            fg=C["fg_muted"],
            font=(C["font_mono"], 8),
            wrap=tk.WORD,
            relief=tk.FLAT,
            borderwidth=0,
            padx=8, pady=4,
            state=tk.DISABLED,
        )
        self.logs_text.pack(fill=tk.BOTH, expand=True)
        self.logs_text.tag_configure("ERROR", foreground=C["sev_critical"])
        self.logs_text.tag_configure("WARNING", foreground=C["sev_medium"])
        self.logs_text.tag_configure("INFO", foreground=C["fg_green"])

    def _switch_panel(self, key: str):
        self._active_panel = key
        self._set_active_btn(key)

        # Build panels lazily
        builders = {
            "problems": self._build_sidebar_problems,
            "chat": self._build_sidebar_chat_panel,
            "history": self._build_sidebar_history,
            "logs": self._build_sidebar_logs,
        }
        if key in builders:
            builders[key]()

        panel_map = {
            "explorer": "_panel_explorer",
            "problems": "_panel_problems",
            "chat": "_panel_chat_sidebar",
            "history": "_panel_history_sidebar",
            "logs": "_panel_logs_sidebar",
        }

        for k, attr in panel_map.items():
            if hasattr(self, attr):
                getattr(self, attr).pack_forget()

        target = panel_map.get(key)
        if target and hasattr(self, target):
            getattr(self, target).pack(fill=tk.BOTH, expand=True)

        # If switching to history, refresh
        if key == "history":
            self._refresh_history_table()

    # ── Main Editor Area ───────────────────────────────────────────────────────
    def _build_main_area(self, parent: tk.Frame):
        # Split vertically: editor (top) | bottom panel (tabs)
        self._paned_v = tk.PanedWindow(
            parent,
            orient=tk.VERTICAL,
            bg=C["border"],
            sashwidth=4,
            sashpad=0,
            sashrelief=tk.FLAT,
            handlesize=0,
        )
        self._paned_v.pack(fill=tk.BOTH, expand=True)

        # ── Editor frame ──
        editor_outer = tk.Frame(self._paned_v, bg=C["bg_editor"])
        self._paned_v.add(editor_outer, minsize=200)

        # Tab bar
        self._tabbar = tk.Frame(editor_outer, bg=C["bg_tab_idle"], height=35)
        self._tabbar.pack(fill=tk.X)
        self._tabbar.pack_propagate(False)
        self._editor_tab_lbl = tk.Label(
            self._tabbar,
            text="  Welcome  ",
            bg=C["bg_tab_active"],
            fg=C["fg_default"],
            font=(C["font_ui"], 9),
            padx=12, pady=8,
            anchor="w",
        )
        self._editor_tab_lbl.pack(side=tk.LEFT)
        tk.Frame(self._tabbar, bg=C["border"], width=1).pack(side=tk.LEFT, fill=tk.Y)

        # Editor body (line numbers + text)
        editor_body = tk.Frame(editor_outer, bg=C["bg_editor"])
        editor_body.pack(fill=tk.BOTH, expand=True)

        self.code_text = tk.Text(
            editor_body,
            bg=C["bg_editor"],
            fg=C["fg_default"],
            insertbackground=C["cursor"],
            font=(C["font_mono"], C["font_size"] + 1),
            wrap=tk.NONE,
            padx=16,
            pady=8,
            relief=tk.FLAT,
            borderwidth=0,
            selectbackground=C["bg_select"],
            selectforeground=C["fg_title"],
            undo=True,
        )

        # Configure syntax-like tags
        self.code_text.tag_configure("vuln_highlight",
            background=C["bg_vuln"],
            foreground=C["fg_vuln"],
            font=(C["font_mono"], C["font_size"] + 1, "bold"),
        )
        self.code_text.tag_configure("kw", foreground="#569cd6")
        self.code_text.tag_configure("str_tag", foreground="#ce9178")
        self.code_text.tag_configure("comment", foreground="#6a9955")
        self.code_text.tag_configure("num", foreground="#b5cea8")

        line_nums = _LineNumberCanvas(editor_body, self.code_text)
        line_nums.pack(side=tk.LEFT, fill=tk.Y)

        self.code_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scroll_y = ttk.Scrollbar(editor_body, style="Thin.Vertical.TScrollbar", command=self.code_text.yview)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.code_text.configure(yscrollcommand=scroll_y.set)

        scroll_x = ttk.Scrollbar(editor_outer, style="Thin.Horizontal.TScrollbar",
                                  orient=tk.HORIZONTAL, command=self.code_text.xview)
        scroll_x.pack(fill=tk.X)
        self.code_text.configure(xscrollcommand=scroll_x.set)

        # Welcome message
        self._show_welcome()

        # ── Bottom Panel ──
        bottom_outer = tk.Frame(self._paned_v, bg=C["bg_sidebar"])
        self._paned_v.add(bottom_outer, minsize=120)

        self._build_bottom_panel(bottom_outer)

    def _show_welcome(self):
        msg = (
            "\n"
            "  Secure Code Forensics IDE\n"
            "  ─────────────────────────────────────────────────\n\n"
            "  ▶  Open Folder    – load any project directory\n"
            "  ▶  Run Scan       – multi-language AST + RAG + LLM pipeline\n"
            "  ▶  Apply Patch    – one-click unified diff patch to disk\n"
            "  ▶  AI Chat        – ask security questions about your code\n\n"
            "  Supported: C, C++, Python, Java, JavaScript, TypeScript\n"
        )
        self.code_text.configure(state=tk.NORMAL)
        self.code_text.delete("1.0", tk.END)
        self.code_text.insert(tk.END, msg)
        self.code_text.configure(state=tk.DISABLED)

    # ── Bottom Panel (tabs: Problems, Explain, Patch) ─────────────────────────
    def _build_bottom_panel(self, parent: tk.Frame):
        # Tab bar
        tab_bar = tk.Frame(parent, bg=C["bg_sidebar"], height=32)
        tab_bar.pack(fill=tk.X)
        tab_bar.pack_propagate(False)

        self._bottom_tabs: Dict[str, tk.Frame] = {}
        self._bottom_tab_btns: Dict[str, tk.Label] = {}
        self._active_bottom_tab = ""

        tab_defs = [
            ("problems",  "⚠  Problems"),
            ("explain",   "💡  Evidence"),
            ("patch",     "🔧  Patch"),
        ]

        for key, label in tab_defs:
            btn = tk.Label(
                tab_bar,
                text=f"  {label}  ",
                bg=C["bg_sidebar"],
                fg=C["fg_muted"],
                font=(C["font_ui"], 9),
                cursor="hand2",
                padx=4, pady=6,
            )
            btn.pack(side=tk.LEFT)
            btn.bind("<Button-1>", lambda e, k=key: self._switch_bottom_tab(k))
            self._bottom_tab_btns[key] = btn

        # Separator under tab bar
        tk.Frame(parent, bg=C["border"], height=1).pack(fill=tk.X)

        # Content area
        content = tk.Frame(parent, bg=C["bg_editor"])
        content.pack(fill=tk.BOTH, expand=True)

        # Problems tab
        self._build_problems_tab(content)
        # Explain tab
        self._build_explain_tab(content)
        # Patch tab
        self._build_patch_tab(content)

        self._switch_bottom_tab("problems")

    def _switch_bottom_tab(self, key: str):
        self._active_bottom_tab = key
        for k, btn in self._bottom_tab_btns.items():
            if k == key:
                btn.configure(bg=C["bg_editor"], fg=C["fg_default"])
            else:
                btn.configure(bg=C["bg_sidebar"], fg=C["fg_muted"])

        for k, frame in self._bottom_tabs.items():
            if k == key:
                frame.pack(fill=tk.BOTH, expand=True)
            else:
                frame.pack_forget()

    def _build_problems_tab(self, parent: tk.Frame):
        frame = tk.Frame(parent, bg=C["bg_editor"])
        self._bottom_tabs["problems"] = frame

        cols = ("severity", "confidence", "cwe", "function", "file", "line")
        self.problems_table = ttk.Treeview(
            frame,
            style="Problems.Treeview",
            columns=cols,
            show="headings",
        )

        headings = [
            ("severity",   "Severity",   80),
            ("confidence", "Confidence", 80),
            ("cwe",        "CWE / CVE",  130),
            ("function",   "Function",   140),
            ("file",       "File",       280),
            ("line",       "Lines",       70),
        ]
        for col, text, w in headings:
            self.problems_table.heading(col, text=text, anchor=tk.W)
            self.problems_table.column(col, width=w, anchor=tk.W)

        # Severity colours via row tags
        self.problems_table.tag_configure("Critical", foreground=C["sev_critical"])
        self.problems_table.tag_configure("High",     foreground=C["sev_high"])
        self.problems_table.tag_configure("Medium",   foreground=C["sev_medium"])
        self.problems_table.tag_configure("Low",      foreground=C["sev_low"])

        self.problems_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.problems_table.bind("<<TreeviewSelect>>", self._on_problem_select)

        sb = ttk.Scrollbar(frame, style="Thin.Vertical.TScrollbar", command=self.problems_table.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.problems_table.configure(yscrollcommand=sb.set)

    def _build_explain_tab(self, parent: tk.Frame):
        frame = tk.Frame(parent, bg=C["bg_editor"])
        self._bottom_tabs["explain"] = frame

        self.explain_text = tk.Text(
            frame,
            bg=C["bg_editor"],
            fg=C["fg_default"],
            font=(C["font_ui"], 9),
            wrap=tk.WORD,
            relief=tk.FLAT,
            borderwidth=0,
            padx=20, pady=12,
            state=tk.DISABLED,
        )
        self.explain_text.tag_configure("heading", foreground=C["fg_accent"],
                                         font=(C["font_ui"], 10, "bold"))
        self.explain_text.tag_configure("sub", foreground=C["fg_green"],
                                         font=(C["font_ui"], 9, "bold"))
        self.explain_text.tag_configure("code_inline", foreground=C["fg_orange"],
                                         font=(C["font_mono"], 9))
        self.explain_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        sb = ttk.Scrollbar(frame, style="Thin.Vertical.TScrollbar", command=self.explain_text.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.explain_text.configure(yscrollcommand=sb.set)

    def _build_patch_tab(self, parent: tk.Frame):
        frame = tk.Frame(parent, bg=C["bg_editor"])
        self._bottom_tabs["patch"] = frame

        # Patch action bar
        action_bar = tk.Frame(frame, bg=C["bg_sidebar"], pady=4)
        action_bar.pack(fill=tk.X)

        self.apply_patch_btn = tk.Button(
            action_bar,
            text="  Apply Patch to File  ",
            bg=C["fg_accent"],
            fg=C["bg_editor"],
            activebackground="#4080b0",
            activeforeground=C["fg_title"],
            font=(C["font_ui"], 9, "bold"),
            relief=tk.FLAT,
            cursor="hand2",
            state=tk.DISABLED,
            command=self._apply_active_patch,
            padx=8,
        )
        self.apply_patch_btn.pack(side=tk.LEFT, padx=12, pady=2)

        self.patch_status_lbl = tk.Label(
            action_bar,
            text="Select a problem to preview the patch",
            bg=C["bg_sidebar"],
            fg=C["fg_muted"],
            font=(C["font_ui"], 9, "italic"),
        )
        self.patch_status_lbl.pack(side=tk.LEFT)

        tk.Frame(frame, bg=C["border"], height=1).pack(fill=tk.X)

        # Diff viewer
        diff_frame = tk.Frame(frame, bg=C["bg_editor"])
        diff_frame.pack(fill=tk.BOTH, expand=True)

        self.patch_diff_text = tk.Text(
            diff_frame,
            bg=C["bg_editor"],
            fg=C["fg_default"],
            font=(C["font_mono"], 9),
            wrap=tk.NONE,
            relief=tk.FLAT,
            borderwidth=0,
            padx=16, pady=8,
            state=tk.DISABLED,
        )
        self.patch_diff_text.tag_configure("added",   foreground="#4ec9b0", background="#12262e")
        self.patch_diff_text.tag_configure("removed",  foreground=C["sev_critical"], background="#2d1515")
        self.patch_diff_text.tag_configure("meta",     foreground=C["fg_muted"])

        self.patch_diff_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(diff_frame, style="Thin.Vertical.TScrollbar", command=self.patch_diff_text.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.patch_diff_text.configure(yscrollcommand=sb.set)

    # ── Status Bar ─────────────────────────────────────────────────────────────
    def _build_statusbar(self):
        bar = tk.Frame(self, bg=C["bg_statusbar"], height=22)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)

        self._status_lbl = tk.Label(
            bar,
            text="  Ready  |  Multi-Language AST + RAG + LoRA Engine",
            bg=C["bg_statusbar"],
            fg=C["fg_title"],
            font=(C["font_ui"], 8),
            anchor="w",
        )
        self._status_lbl.pack(side=tk.LEFT, padx=4)

        self._status_right = tk.Label(
            bar,
            text="Python · UTF-8  ",
            bg=C["bg_statusbar"],
            fg=C["fg_title"],
            font=(C["font_ui"], 8),
            anchor="e",
        )
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
        self._log_msg(f"Opened: {self.current_project_folder}", "INFO")
        self._set_status(f"Opened: {self.current_project_folder}", short)
        self._switch_panel("explorer")

    def _populate_file_tree(self, root_path: str):
        self.file_tree.delete(*self.file_tree.get_children())
        node_map: Dict[str, str] = {}

        for root, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if not self.config_mgr.is_ignored_dir(d)]
            rel_path = os.path.relpath(root, root_path)
            parent_id = ""
            if rel_path != ".":
                parent_key = os.path.dirname(rel_path) if os.path.dirname(rel_path) else ""
                parent_id = node_map.get(parent_key, "")
                dir_id = self.file_tree.insert(
                    parent_id, "end",
                    text=f"  {os.path.basename(root)}",
                    open=True,
                )
                node_map[rel_path] = dir_id
            else:
                node_map[""] = ""

            dir_id = node_map.get(rel_path, "")
            for fname in sorted(files):
                ext = os.path.splitext(fname)[1].lower()
                if self.config_mgr.is_supported_extension(ext):
                    full_f = os.path.join(root, fname)
                    badge = self.file_badges.get(full_f, "")
                    self.file_tree.insert(
                        dir_id, "end",
                        text=f"  {fname}",
                        values=(badge,),
                        tags=(full_f,),
                    )

    def _start_scan_thread(self):
        if not self.current_project_folder:
            messagebox.showwarning("No Project", "Open a project folder first.")
            return
        if self.is_scanning:
            return
        self.is_scanning = True
        self._btn_scan.configure_state(False)
        self._btn_scan._lbl.configure(text="  ⏳  Scanning…  ")
        self._set_status("Scanning… multi-language AST + RAG + LLM pipeline running")
        threading.Thread(target=self._run_scan_pipeline, daemon=True).start()

    def _run_scan_pipeline(self):
        import time
        try:
            start_t = time.time()
            force_reparse = not self.incremental_var.get()
            self._log_msg(f"Scan started on {self.current_project_folder} (incremental={not force_reparse})", "INFO")

            parser_res = self.parser_module.scan_project(self.current_project_folder, force_reparse=force_reparse)
            file_results = parser_res.get("file_results", {})
            scanned = parser_res.get("files_scanned", 0)

            self.current_scan_id = self.persistence.create_scan_run(
                self.current_project_id or 1, scanned, 0
            )

            all_findings: List[Dict[str, Any]] = []
            self.file_badges.clear()

            for fpath, analysis in file_results.items():
                lang = analysis.get("language", "unknown")
                correlated = self.correlation_module.correlate_file_findings(fpath, lang, analysis)
                file_count = 0

                for corr in correlated:
                    llm_resp: Dict[str, Any] = {}
                    try:
                        if self.llm_engine.check_connection().get("status") == "ONLINE":
                            prompt = self.prompt_builder.build_verification_prompt(
                                corr, corr.get("rag_context", {}), lang
                            )
                            llm_resp = self.llm_engine.execute_inference(prompt)
                    except Exception:
                        pass

                    verified = self.verification_module.verify_finding(corr, llm_resp)
                    if verified.get("severity") != "Info" and verified.get("confidence", 0) >= 40:
                        patch_info = self.patch_module.generate_patch_for_finding(verified)
                        verified["patch_diff"] = patch_info.get("unified_diff", "")
                        verified["patched_snippet"] = patch_info.get("patched_snippet", "")
                        verified["explanation_json"] = self.explainability_module.generate_evidence_explanation(verified)
                        all_findings.append(verified)
                        file_count += 1

                if file_count > 0:
                    self.file_badges[fpath] = f"● {file_count}"

            self.persistence.save_vulnerabilities(self.current_scan_id, all_findings)
            self.persistence.update_scan_findings_count(self.current_scan_id, len(all_findings))
            self.vulnerabilities_list = sorted(
                all_findings,
                key=lambda x: (x.get("cvss_score", 0), x.get("confidence", 0)),
                reverse=True,
            )

            elapsed = round(time.time() - start_t, 3)
            msg = (
                f"Scan done in {elapsed}s  |  "
                f"{scanned} files  ({parser_res.get('files_from_cache', 0)} cached)  |  "
                f"{len(self.vulnerabilities_list)} findings"
            )
            self._log_msg(msg, "INFO")
            self.persistence.log_scan_message(self.current_scan_id, msg)
            self.after(10, lambda: self._on_scan_completed(msg))
        except Exception as exc:
            self.after(10, lambda: self._on_scan_error(str(exc)))

    def _on_scan_completed(self, msg: str):
        self.is_scanning = False
        self._btn_scan._lbl.configure(text="  ▶  Run Scan  ")
        self._btn_scan.configure_state(True)
        self._set_status(msg)
        self._populate_file_tree(self.current_project_folder)
        self._refresh_problems_table()
        self._refresh_history_table()
        self._switch_bottom_tab("problems")

    def _on_scan_error(self, err: str):
        self.is_scanning = False
        self._btn_scan._lbl.configure(text="  ▶  Run Scan  ")
        self._btn_scan.configure_state(True)
        self._set_status(f"Scan error: {err}")
        self._log_msg(f"Scan failed: {err}", "ERROR")
        messagebox.showerror("Scan Error", err)

    # ── Table refresh ──────────────────────────────────────────────────────────
    def _refresh_problems_table(self):
        self.problems_table.delete(*self.problems_table.get_children())

        # Also refresh sidebar list if present
        if hasattr(self, "_problems_sidebar_list"):
            self._problems_sidebar_list.delete(0, tk.END)

        for idx, item in enumerate(self.vulnerabilities_list):
            sev = item.get("severity", "High")
            conf = item.get("confidence", 65)
            cwe = f"{item.get('cwe', 'Unknown')}  {item.get('cve', '')}".strip()
            func = item.get("function_name", "unknown")
            fpath = (
                os.path.relpath(item.get("file_path", ""), self.current_project_folder)
                if self.current_project_folder else item.get("file_path", "")
            )
            lines = f"{item.get('start_line', 1)}–{item.get('end_line', 1)}"

            self.problems_table.insert(
                "", "end", iid=str(idx),
                values=(sev, f"{conf}%", cwe, func, fpath, lines),
                tags=(sev,),
            )

            if hasattr(self, "_problems_sidebar_list"):
                icon = "⬤" if sev == "Critical" else ("▲" if sev == "High" else "▸")
                self._problems_sidebar_list.insert(
                    tk.END, f"  {icon}  {sev}  {os.path.basename(fpath)}:{item.get('start_line', 1)}"
                )

    def _refresh_history_table(self):
        if not hasattr(self, "history_table"):
            return
        self.history_table.delete(*self.history_table.get_children())
        history = self.persistence.list_scan_history(self.current_project_id)
        for h in history:
            ts = h.get("timestamp", "")[:19].replace("T", " ")
            self.history_table.insert(
                "", "end",
                values=(h.get("id"), ts, h.get("file_count", 0), h.get("findings_count", 0)),
            )

    # ── Selection handlers ─────────────────────────────────────────────────────
    def _on_file_tree_select(self, event):
        selected = self.file_tree.selection()
        if not selected:
            return
        tags = self.file_tree.item(selected[0], "tags")
        if tags and os.path.isfile(tags[0]):
            self._display_file_in_editor(tags[0])

    def _on_sidebar_problem_click(self, event):
        sel = self._problems_sidebar_list.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx < len(self.vulnerabilities_list):
            self._select_finding(idx)

    def _display_file_in_editor(self, file_path: str, highlight_line: Optional[int] = None):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            self.active_file_path = file_path

            # Update tab label
            fname = os.path.basename(file_path)
            self._editor_tab_lbl.configure(text=f"  {fname}  ")

            ext = os.path.splitext(file_path)[1]
            self._status_right.configure(text=f"{ext.lstrip('.').upper() or 'Text'} · UTF-8  ")

            self.code_text.configure(state=tk.NORMAL)
            self.code_text.delete("1.0", tk.END)
            self.code_text.insert(tk.END, content)

            if highlight_line and highlight_line > 0:
                start_idx = f"{highlight_line}.0"
                end_idx = f"{highlight_line}.end"
                self.code_text.tag_remove("vuln_highlight", "1.0", tk.END)
                self.code_text.tag_add("vuln_highlight", start_idx, end_idx)
                self.code_text.see(f"{max(1, highlight_line - 4)}.0")
        except Exception as exc:
            self._log_msg(f"Cannot read {file_path}: {exc}", "WARNING")

    def _on_problem_select(self, event):
        selected = self.problems_table.selection()
        if not selected:
            return
        self._select_finding(int(selected[0]))

    def _select_finding(self, idx: int):
        if not (0 <= idx < len(self.vulnerabilities_list)):
            return
        item = self.vulnerabilities_list[idx]
        self.active_finding = item

        # Open & highlight in editor
        fpath = item.get("file_path", "")
        if os.path.exists(fpath):
            self._display_file_in_editor(fpath, highlight_line=item.get("start_line", 1))

        # Evidence panel
        exp = item.get("explanation_json", {})
        md_text = exp.get("markdown_report", "") if isinstance(exp, dict) else ""
        if not md_text:
            sev = item.get("severity", "?")
            cwe = item.get("cwe", "?")
            func = item.get("function_name", "?")
            score = item.get("cvss_score", 0)
            conf = item.get("confidence", 0)
            md_text = (
                f"[Root Cause Analysis]\n{item.get('sink', 'Unknown')} vulnerability detected in `{func}`\n\n"
                f"Severity: {sev}  |  CWE: {cwe}  |  CVSS: {score}  |  Confidence: {conf}%"
            )

        self.explain_text.configure(state=tk.NORMAL)
        self.explain_text.delete("1.0", tk.END)
        self.explain_text.insert(tk.END, md_text)
        self.explain_text.configure(state=tk.DISABLED)

        # Patch diff panel
        diff_text = item.get("patch_diff", "")
        self.patch_diff_text.configure(state=tk.NORMAL)
        self.patch_diff_text.delete("1.0", tk.END)
        if diff_text:
            for line in diff_text.splitlines(keepends=True):
                if line.startswith("+") and not line.startswith("+++"):
                    self.patch_diff_text.insert(tk.END, line, "added")
                elif line.startswith("-") and not line.startswith("---"):
                    self.patch_diff_text.insert(tk.END, line, "removed")
                elif line.startswith("@@") or line.startswith("---") or line.startswith("+++"):
                    self.patch_diff_text.insert(tk.END, line, "meta")
                else:
                    self.patch_diff_text.insert(tk.END, line)
            self.apply_patch_btn.configure(state=tk.NORMAL)
            fname = os.path.basename(fpath)
            self.patch_status_lbl.configure(text=f"Fix ready for {item.get('cwe', '?')} in {fname}")
        else:
            self.patch_diff_text.insert(tk.END, "  // No automated patch generated for this finding.")
            self.apply_patch_btn.configure(state=tk.DISABLED)
        self.patch_diff_text.configure(state=tk.DISABLED)

    def _on_history_double_click(self, event):
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
            self._log_msg(f"Loaded {len(loaded)} findings from scan #{scan_id}", "INFO")

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
                messagebox.showinfo("Patch Applied", f"✓ Patch applied to:\n{fpath}")
                self._display_file_in_editor(fpath, highlight_line=self.active_finding.get("start_line", 1))
                self._log_msg(f"Patch applied: {fpath}", "INFO")
            else:
                messagebox.showwarning("Alignment", "Original snippet not found — review the unified diff manually.")
        except Exception as exc:
            messagebox.showerror("Write Error", str(exc))

    # ── Chat ───────────────────────────────────────────────────────────────────
    def _send_chat_question(self):
        if not hasattr(self, "chat_entry"):
            return
        question = self.chat_entry.get().strip()
        if not question:
            return
        self.chat_entry.delete(0, tk.END)

        self.chat_display.configure(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"\n  You  ", "user_tag")
        self.chat_display.insert(tk.END, f"\n  {question}\n")
        self.chat_display.see(tk.END)
        self.chat_display.configure(state=tk.DISABLED)

        code_ctx = (
            self.code_text.get("1.0", tk.END)[:1500]
            if self.active_file_path else "No file opened."
        )
        rag_ctx = (
            self.active_finding.get("correlated_item", {}).get("rag_context", {})
            if self.active_finding else {}
        )

        conn = self.llm_engine.check_connection()
        if conn.get("status") != "ONLINE":
            self.chat_display.configure(state=tk.NORMAL)
            self.chat_display.insert(tk.END, f"\n  AI  ", "ai_tag")
            self.chat_display.insert(
                tk.END,
                f"\n  LLM backend offline ({conn.get('provider', '?')}).\n"
                f"  No simulated responses — start Ollama or configure your endpoint in Settings.\n",
                "err_tag",
            )
            self.chat_display.see(tk.END)
            self.chat_display.configure(state=tk.DISABLED)
            return

        def run_chat():
            try:
                prompt = self.prompt_builder.build_chat_prompt(question, code_ctx, "c", rag_ctx)
                self.chat_display.configure(state=tk.NORMAL)
                self.chat_display.insert(tk.END, f"\n  AI  ", "ai_tag")
                self.chat_display.insert(tk.END, "\n  ")
                for token in self.llm_engine.stream_chat(prompt):
                    self.chat_display.insert(tk.END, token)
                    self.chat_display.see(tk.END)
                self.chat_display.insert(tk.END, "\n")
                self.chat_display.see(tk.END)
                self.chat_display.configure(state=tk.DISABLED)
                if self.current_project_id:
                    self.persistence.save_chat_message(
                        self.current_project_id, question, "", {"file": self.active_file_path}
                    )
            except LLMBackendOfflineError as exc:
                self.chat_display.configure(state=tk.NORMAL)
                self.chat_display.insert(tk.END, f"\n  [Error]: {exc}\n", "err_tag")
                self.chat_display.see(tk.END)
                self.chat_display.configure(state=tk.DISABLED)

        threading.Thread(target=run_chat, daemon=True).start()

    # ── Settings ───────────────────────────────────────────────────────────────
    def _open_settings_dialog(self):
        win = tk.Toplevel(self)
        win.title("Settings")
        win.geometry("520x380")
        win.configure(bg=C["bg_sidebar"])
        win.resizable(False, False)

        def _label(text):
            tk.Label(win, text=text, bg=C["bg_sidebar"], fg=C["fg_muted"],
                     font=(C["font_ui"], 9, "bold"), anchor="w").pack(
                fill=tk.X, padx=20, pady=(14, 2))

        def _entry(var):
            e = tk.Entry(win, textvariable=var, bg=C["bg_input"], fg=C["fg_default"],
                         insertbackground=C["cursor"], relief=tk.FLAT,
                         font=(C["font_mono"], 9))
            e.pack(fill=tk.X, padx=20)
            return e

        tk.Label(win, text="  Settings", bg=C["bg_titlebar"], fg=C["fg_title"],
                 font=(C["font_ui"], 11, "bold"), anchor="w", pady=10).pack(fill=tk.X)

        _label("LLM Provider")
        provider_var = tk.StringVar(value=self.config_mgr.get("llm_provider", "ollama"))
        cb = ttk.Combobox(win, textvariable=provider_var,
                          values=["ollama", "openai_compatible", "huggingface_lora"])
        cb.pack(fill=tk.X, padx=20)

        _label("LLM Endpoint URL")
        endpoint_var = tk.StringVar(value=self.config_mgr.get("llm_endpoint", "http://localhost:11434/api/chat"))
        _entry(endpoint_var)

        _label("Model Name / LoRA Path")
        model_var = tk.StringVar(value=self.config_mgr.get("llm_model", "deepseek-coder:6.7b"))
        _entry(model_var)

        def _save():
            self.config_mgr.set("llm_provider", provider_var.get())
            self.config_mgr.set("llm_endpoint", endpoint_var.get())
            self.config_mgr.set("llm_model", model_var.get())
            self.config_mgr.save_config()
            self._log_msg(f"Settings saved: provider={provider_var.get()}", "INFO")
            win.destroy()

        tk.Button(
            win, text="  Save  ", bg=C["fg_accent"], fg=C["bg_editor"],
            font=(C["font_ui"], 9, "bold"), relief=tk.FLAT,
            cursor="hand2", command=_save, padx=16,
        ).pack(pady=20)

    # ── Logging ────────────────────────────────────────────────────────────────
    def _log_msg(self, msg: str, level: str = "INFO"):
        if not hasattr(self, "logs_text"):
            return
        ts = datetime.now().strftime("%H:%M:%S")
        self.logs_text.configure(state=tk.NORMAL)
        self.logs_text.insert(tk.END, f"[{ts}] ", "INFO")
        self.logs_text.insert(tk.END, f"[{level}] ", level)
        self.logs_text.insert(tk.END, f"{msg}\n")
        self.logs_text.see(tk.END)
        self.logs_text.configure(state=tk.DISABLED)
