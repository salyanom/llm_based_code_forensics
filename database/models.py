from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


class ScanRepository:
    def __init__(self, db_path: str = "scan_sessions.db"):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True) if os.path.dirname(self.db_path) else None
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    scan_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    query_text TEXT,
                    file_count INTEGER NOT NULL,
                    report_json TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    function_name TEXT,
                    vulnerability_type TEXT NOT NULL,
                    severity TEXT,
                    cwe TEXT,
                    cve TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    line_number INTEGER,
                    explanation TEXT,
                    threat_intel_match INTEGER DEFAULT 0,
                    patch_text TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scan_sessions(scan_id)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    vulnerability_id INTEGER,
                    is_false_positive INTEGER NOT NULL,
                    comment TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scan_sessions(scan_id),
                    FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id)
                )
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_feedback_scan_id ON feedback(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_sessions_created_at ON scan_sessions(created_at DESC)")
            conn.commit()

    def save_scan(self, query_text: str, report: Dict[str, Any]) -> str:
        scan_id = report.get("scan_id") or str(uuid.uuid4())
        created_at = datetime.utcnow().isoformat()
        vulnerabilities = report.get("vulnerabilities", [])

        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scan_sessions(scan_id, created_at, query_text, file_count, report_json)
                VALUES(?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    created_at,
                    query_text,
                    len(report.get("files_scanned", [])),
                    json.dumps(report),
                ),
            )

            for item in vulnerabilities:
                cursor.execute(
                    """
                    INSERT INTO vulnerabilities(
                        scan_id, file_name, function_name, vulnerability_type, severity, cwe, cve,
                        cvss_score, cvss_vector, line_number, explanation, threat_intel_match, patch_text
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        item.get("file", "unknown"),
                        item.get("function_name", "unknown"),
                        item.get("type", "Unknown"),
                        item.get("severity", "Unknown"),
                        item.get("cwe", "Unknown"),
                        item.get("cve", "Unknown"),
                        item.get("cvss_score"),
                        item.get("cvss_vector", ""),
                        item.get("line"),
                        item.get("explanation", ""),
                        1 if item.get("threat_intel_match") else 0,
                        item.get("patch", ""),
                    ),
                )

            conn.commit()

        return scan_id

    def add_feedback(self, scan_id: str, vulnerability_id: Optional[int], is_false_positive: bool, comment: str = ""):
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO feedback(scan_id, vulnerability_id, is_false_positive, comment, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (scan_id, vulnerability_id, 1 if is_false_positive else 0, comment, datetime.utcnow().isoformat()),
            )
            conn.commit()

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT report_json FROM scan_sessions WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return json.loads(row[0])

    def list_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT scan_id, created_at, query_text, file_count FROM scan_sessions ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()

        return [
            {
                "scan_id": row[0],
                "created_at": row[1],
                "query": row[2],
                "file_count": row[3],
            }
            for row in rows
        ]
