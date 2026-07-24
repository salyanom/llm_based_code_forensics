import os
import json
import hashlib
from typing import Any, Dict, List

from core.knowledge.threat.normalizer import ThreatNormalizer

class ThreatLoader:
    """
    Extracted from modules/dataset_preprocessing.py.
    Responsible for loading raw threat intelligence feeds (NVD, OWASP, CWE, CAPEC, CISA KEV).
    """

    def __init__(self, knowledge_dir: str):
        self.knowledge_dir = knowledge_dir

    @staticmethod
    def _compute_hash(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

    def load_owasp(self) -> List[Dict[str, Any]]:
        owasp_path = os.path.join(self.knowledge_dir, "owasp.json")
        records: List[Dict[str, Any]] = []
        if not os.path.exists(owasp_path):
            return records
        try:
            with open(owasp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            seq = data if isinstance(data, list) else [data]
            for item in seq:
                text = ThreatNormalizer.clean_text(item.get("description") or item.get("text") or "")
                if len(text) < 10:
                    continue
                records.append({
                    "source": "OWASP",
                    "cwe": ThreatNormalizer.normalize_cwe(item.get("cwe")),
                    "cve": "Unknown",
                    "cleaned_code": text,
                    "description": text,
                    "title": item.get("title") or item.get("id") or "OWASP Item",
                    "content_hash": self._compute_hash(text),
                })
        except Exception as exc:
            print(f"[ThreatLoader] Error loading OWASP: {exc}")
        return records

    def load_nvd(self) -> List[Dict[str, Any]]:
        nvd_path = os.path.join(self.knowledge_dir, "nvd.json")
        records: List[Dict[str, Any]] = []
        if not os.path.exists(nvd_path):
            return records
        try:
            with open(nvd_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            seq = data if isinstance(data, list) else [data]
            for item in seq:
                desc = ThreatNormalizer.clean_text(item.get("description") or item.get("summary") or "")
                if len(desc) < 10:
                    continue
                records.append({
                    "source": "NVD",
                    "cwe": ThreatNormalizer.normalize_cwe(item.get("cwe")),
                    "cve": ThreatNormalizer.normalize_cve(item.get("cve") or item.get("id")),
                    "cleaned_code": desc,  # For compatibility with legacy format
                    "description": desc,
                    "title": item.get("id") or "NVD Entry",
                    "content_hash": self._compute_hash(desc),
                })
        except Exception as exc:
            print(f"[ThreatLoader] Error loading NVD: {exc}")
        return records
