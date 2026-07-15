from __future__ import annotations

import hashlib
import json
import os
import re
from glob import glob
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


class DatasetPreprocessingModule:
    """Dedicated preprocessing pipeline for cleaning, normalizing, and merging security datasets."""

    def __init__(self, root_dir: Optional[str] = None):
        self.root_dir = root_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.data_dir = os.path.join(self.root_dir, "data")
        self.knowledge_dir = os.path.join(self.root_dir, "knowledge")
        os.makedirs(self.data_dir, exist_ok=True)

    @staticmethod
    def _compute_hash(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def _normalize_cwe(raw: Any) -> str:
        if raw is None:
            return "Unknown"
        if isinstance(raw, list):
            raw = raw[0] if raw else "Unknown"
        val = str(raw).strip()
        if not val or val.lower() == "unknown":
            return "Unknown"
        if val.isdigit():
            return f"CWE-{val}"
        match = re.search(r"CWE-(\d+)", val, re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)}"
        return val

    @staticmethod
    def _normalize_cve(raw: Any) -> str:
        if raw is None:
            return "Unknown"
        if isinstance(raw, list):
            raw = raw[0] if raw else "Unknown"
        val = str(raw).strip()
        match = re.search(r"CVE-\d{4}-\d+", val, re.IGNORECASE)
        if match:
            return match.group(0).upper()
        return "Unknown"

    @staticmethod
    def _clean_code(text: str) -> str:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        lines = [line.rstrip() for line in text.split("\n")]
        cleaned = "\n".join(lines).strip()
        while "\n\n\n" in cleaned:
            cleaned = cleaned.replace("\n\n\n", "\n\n")
        return cleaned

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
                code = self._clean_code(item.get("code") or item.get("source") or item.get("snippet") or "")
                if len(code) < 15:
                    continue
                title = item.get("title") or item.get("id") or "juliet_case"
                desc = item.get("description") or item.get("summary") or ""
                cwe = self._normalize_cwe(item.get("cwe") or title)
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
            print(f"[DatasetPreprocessing] Error loading Juliet: {exc}")
        return records

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
                text = self._clean_code(item.get("description") or item.get("text") or "")
                if len(text) < 10:
                    continue
                records.append({
                    "source": "OWASP",
                    "cwe": self._normalize_cwe(item.get("cwe")),
                    "cve": "Unknown",
                    "cleaned_code": text,
                    "description": text,
                    "title": item.get("title") or item.get("id") or "OWASP Item",
                    "content_hash": self._compute_hash(text),
                })
        except Exception as exc:
            print(f"[DatasetPreprocessing] Error loading OWASP: {exc}")
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
                desc = self._clean_code(item.get("description") or item.get("summary") or "")
                if len(desc) < 10:
                    continue
                records.append({
                    "source": "NVD",
                    "cwe": self._normalize_cwe(item.get("cwe")),
                    "cve": self._normalize_cve(item.get("cve") or item.get("id")),
                    "cleaned_code": desc,
                    "description": desc,
                    "title": item.get("id") or "NVD Entry",
                    "content_hash": self._compute_hash(desc),
                })
        except Exception as exc:
            print(f"[DatasetPreprocessing] Error loading NVD: {exc}")
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
                        code = self._clean_code(f.read())
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

    def load_and_preprocess(self) -> Dict[str, Any]:
        """Alias for run_preprocessing_pipeline."""
        return self.run_preprocessing_pipeline()

    def run_preprocessing_pipeline(self) -> Dict[str, Any]:
        """Execute full normalization, deduplication, and export of training JSONL."""
        print("[DatasetPreprocessing] Starting dataset preprocessing pipeline...")
        records: List[Dict[str, Any]] = []
        records.extend(self.load_juliet())
        records.extend(self.load_owasp())
        records.extend(self.load_nvd())
        records.extend(self.load_code_samples())

        # Deduplicate
        seen_hashes: Set[str] = set()
        unique_records: List[Dict[str, Any]] = []
        for rec in records:
            h = rec["content_hash"]
            if h not in seen_hashes:
                seen_hashes.add(h)
                unique_records.append(rec)

        # Export canonical prompt-completion merged dataset
        merged_path = os.path.join(self.data_dir, "merged_dataset.jsonl")
        count = 0
        with open(merged_path, "w", encoding="utf-8") as out:
            for rec in unique_records:
                prompt = (
                    f"Analyze the following {rec['source']} sample ({rec['cwe']}) for security issues and return JSON:\n"
                    f"Code/Text:\n{rec['cleaned_code']}\n\nRespond only with JSON."
                )
                completion = json.dumps({
                    "vulnerabilities": [{
                        "type": rec["cwe"],
                        "cve": rec["cve"],
                        "description": rec["description"],
                    }],
                    "suggested_patch": "Review input boundaries and apply sanitization." if rec["source"] in {"Juliet", "CodeSample"} else ""
                }, ensure_ascii=False)

                row = {
                    "prompt": prompt,
                    "completion": completion,
                    "meta": {
                        "source": rec["source"],
                        "cwe": rec["cwe"],
                        "cve": rec["cve"],
                        "title": rec["title"],
                        "content_hash": rec["content_hash"],
                    }
                }
                out.write(json.dumps(row, ensure_ascii=False) + "\n")
                count += 1

        print(f"[DatasetPreprocessing] Successfully preprocessed and wrote {count} records to {merged_path}.")
        return {
            "total_raw": len(records),
            "unique_records": len(unique_records),
            "output_path": merged_path,
        }
