import os
import json
import hashlib
from glob import glob
from typing import Any, Dict, List

from core.datasets.normalization import DatasetNormalizer

class DatasetLoader:
    """
    Extracted from modules/dataset_preprocessing.py.
    Responsible for loading raw offline vulnerability datasets (Juliet, CodeSamples, etc.).
    """

    def __init__(self, root_dir: str, knowledge_dir: str):
        self.root_dir = root_dir
        self.knowledge_dir = knowledge_dir

    @staticmethod
    def _compute_hash(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

    def load_juliet(self) -> List[Dict[str, Any]]:
        juliet_path = os.path.join(self.knowledge_dir, "juliet.json")
        records: List[Dict[str, Any]] = []
        if not os.path.exists(juliet_path):
            return records
        try:
            with open(juliet_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            seq = data if isinstance(data, list) else [data]
            for item in seq:
                code = DatasetNormalizer.clean_code(item.get("code") or item.get("source") or item.get("snippet") or "")
                if len(code) < 15:
                    continue
                title = item.get("title") or item.get("id") or "juliet_case"
                desc = item.get("description") or item.get("summary") or ""
                cwe = DatasetNormalizer.normalize_cwe(item.get("cwe") or title)
                records.append({
                    "source": "Juliet",
                    "cwe": cwe,
                    "cve": "Unknown",
                    "cleaned_code": code,
                    "description": desc,
                    "title": title,
                    "content_hash": self._compute_hash(code),
                })
        except Exception as exc:
            print(f"[DatasetLoader] Error loading Juliet: {exc}")
        return records

    def load_code_samples(self) -> List[Dict[str, Any]]:
        code_dir = os.path.join(self.root_dir, "code_samples")
        records: List[Dict[str, Any]] = []
        if not os.path.isdir(code_dir):
            return records
        for ext in ("*.c", "*.cpp", "*.py", "*.js", "*.ts", "*.java"):
            for path in glob(os.path.join(code_dir, "**", ext), recursive=True):
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        code = DatasetNormalizer.clean_code(f.read())
                    if len(code) < 15:
                        continue
                    records.append({
                        "source": "CodeSample",
                        "cwe": "Unknown",
                        "cve": "Unknown",
                        "cleaned_code": code,
                        "description": f"Sample from {os.path.basename(path)}",
                        "title": os.path.basename(path),
                        "content_hash": self._compute_hash(code),
                    })
                except Exception:
                    continue
        return records
