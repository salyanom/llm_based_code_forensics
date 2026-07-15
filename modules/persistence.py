from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from config_manager import ConfigManager


class PersistenceModule:
    """Thread-safe SQLite Persistence & Searchable History manager for the Secure Code Forensics IDE."""

    _instance: Optional["PersistenceModule"] = None
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[str] = None):
        self.config = ConfigManager.get_instance()
        self.root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.db_path = db_path or os.path.join(self.root_dir, self.config.get("db_path", "database/forensics_ide.db"))
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True) if os.path.dirname(self.db_path) else None
        self._db_lock = threading.Lock()
        self._init_schema()

    @classmethod
    def get_instance(cls, db_path: Optional[str] = None) -> "PersistenceModule":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = PersistenceModule(db_path)
        return cls._instance

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._db_lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS projects (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        folder_path TEXT UNIQUE NOT NULL,
                        last_scanned DATETIME NOT NULL
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS scan_runs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        project_id INTEGER NOT NULL,
                        timestamp DATETIME NOT NULL,
                        file_count INTEGER NOT NULL,
                        findings_count INTEGER NOT NULL,
                        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        file_path TEXT NOT NULL,
                        function_name TEXT NOT NULL,
                        start_line INTEGER NOT NULL,
                        end_line INTEGER NOT NULL,
                        sink TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        cwe TEXT NOT NULL,
                        cve TEXT NOT NULL,
                        cvss_score REAL NOT NULL,
                        cvss_vector TEXT NOT NULL,
                        confidence INTEGER NOT NULL,
                        explanation_json TEXT NOT NULL,
                        patch_diff TEXT,
                        patched_snippet TEXT,
                        FOREIGN KEY (scan_id) REFERENCES scan_runs(id) ON DELETE CASCADE
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS scan_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        timestamp DATETIME NOT NULL,
                        level TEXT NOT NULL,
                        message TEXT NOT NULL,
                        FOREIGN KEY (scan_id) REFERENCES scan_runs(id) ON DELETE CASCADE
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS chat_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        project_id INTEGER NOT NULL,
                        timestamp DATETIME NOT NULL,
                        question TEXT NOT NULL,
                        answer TEXT NOT NULL,
                        context_json TEXT,
                        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                    )
                """)
                conn.commit()

    def register_or_get_project(self, folder_path: str) -> int:
        folder_path = os.path.abspath(folder_path)
        now = datetime.now().isoformat()
        with self._db_lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT id FROM projects WHERE folder_path = ?", (folder_path,))
                row = cur.fetchone()
                if row:
                    cur.execute("UPDATE projects SET last_scanned = ? WHERE id = ?", (now, row["id"]))
                    conn.commit()
                    return int(row["id"])
                cur.execute("INSERT INTO projects (folder_path, last_scanned) VALUES (?, ?)", (folder_path, now))
                conn.commit()
                return int(cur.lastrowid)

    def create_scan_run(self, project_id: int, file_count: int, findings_count: int = 0) -> int:
        now = datetime.now().isoformat()
        with self._db_lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO scan_runs (project_id, timestamp, file_count, findings_count) VALUES (?, ?, ?, ?)",
                    (project_id, now, file_count, findings_count),
                )
                conn.commit()
                return int(cur.lastrowid)

    def update_scan_findings_count(self, scan_id: int, count: int) -> None:
        with self._db_lock:
            with self._get_connection() as conn:
                conn.execute("UPDATE scan_runs SET findings_count = ? WHERE id = ?", (count, scan_id))
                conn.commit()

    def save_vulnerabilities(self, scan_id: int, findings: List[Dict[str, Any]]) -> int:
        with self._db_lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                saved = 0
                for f in findings:
                    cur.execute(
                        """INSERT INTO vulnerabilities (
                            scan_id, file_path, function_name, start_line, end_line, sink,
                            severity, cwe, cve, cvss_score, cvss_vector, confidence,
                            explanation_json, patch_diff, patched_snippet
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            scan_id,
                            f.get("file_path", "unknown"),
                            f.get("function_name", "unknown"),
                            f.get("start_line", 1),
                            f.get("end_line", 1),
                            f.get("sink", "unknown"),
                            f.get("severity", "High"),
                            f.get("cwe", "Unknown"),
                            f.get("cve", "Unknown"),
                            float(f.get("cvss_score", 7.5)),
                            f.get("cvss_vector", ""),
                            int(f.get("confidence", 65)),
                            json.dumps(f.get("explanation_json", {}), ensure_ascii=False),
                            f.get("patch_diff", ""),
                            f.get("patched_snippet", ""),
                        ),
                    )
                    saved += 1
                conn.commit()
                return saved

    def log_scan_message(self, scan_id: int, message: str, level: str = "INFO") -> None:
        now = datetime.now().isoformat()
        with self._db_lock:
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT INTO scan_logs (scan_id, timestamp, level, message) VALUES (?, ?, ?, ?)",
                    (scan_id, now, level, message),
                )
                conn.commit()

    def get_scan_logs(self, scan_id: int) -> List[Dict[str, Any]]:
        with self._db_lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT * FROM scan_logs WHERE scan_id = ? ORDER BY id ASC", (scan_id,))
                return [dict(row) for row in cur.fetchall()]

    def list_projects(self) -> List[Dict[str, Any]]:
        with self._db_lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT * FROM projects ORDER BY last_scanned DESC")
                return [dict(row) for row in cur.fetchall()]

    def list_scan_history(self, project_id: Optional[int] = None) -> List[Dict[str, Any]]:
        with self._db_lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                if project_id is not None:
                    cur.execute(
                        """SELECT s.*, p.folder_path FROM scan_runs s
                        JOIN projects p ON s.project_id = p.id
                        WHERE s.project_id = ? ORDER BY s.timestamp DESC""",
                        (project_id,),
                    )
                else:
                    cur.execute(
                        """SELECT s.*, p.folder_path FROM scan_runs s
                        JOIN projects p ON s.project_id = p.id
                        ORDER BY s.timestamp DESC"""
                    )
                return [dict(row) for row in cur.fetchall()]

    def get_scan_vulnerabilities(self, scan_id: int) -> List[Dict[str, Any]]:
        with self._db_lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY cvss_score DESC, confidence DESC", (scan_id,))
                results = []
                for row in cur.fetchall():
                    item = dict(row)
                    try:
                        item["explanation_json"] = json.loads(item["explanation_json"])
                    except Exception:
                        item["explanation_json"] = {}
                    results.append(item)
                return results

    def save_chat_message(self, project_id: int, question: str, answer: str, context: Optional[Dict[str, Any]] = None) -> int:
        now = datetime.now().isoformat()
        with self._db_lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO chat_history (project_id, timestamp, question, answer, context_json) VALUES (?, ?, ?, ?, ?)",
                    (project_id, now, question, answer, json.dumps(context or {}, ensure_ascii=False)),
                )
                conn.commit()
                return int(cur.lastrowid)

    def get_chat_history(self, project_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        with self._db_lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT * FROM chat_history WHERE project_id = ? ORDER BY id DESC LIMIT ?", (project_id, limit))
                results = []
                for row in cur.fetchall():
                    item = dict(row)
                    try:
                        item["context_json"] = json.loads(item.get("context_json") or "{}")
                    except Exception:
                        item["context_json"] = {}
                    results.append(item)
                return list(reversed(results))
