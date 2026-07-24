import re
from typing import Any

class ThreatNormalizer:
    """
    Extracted from modules/dataset_preprocessing.py.
    Responsible for normalizing CWE IDs, CVE IDs, and cleaning text for threat intelligence feeds.
    """

    @staticmethod
    def normalize_cwe(raw: Any) -> str:
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
    def normalize_cve(raw: Any) -> str:
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
    def clean_text(text: str) -> str:
        """Cleans description or code text."""
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        lines = [line.rstrip() for line in text.split("\n")]
        cleaned = "\n".join(lines).strip()
        while "\n\n\n" in cleaned:
            cleaned = cleaned.replace("\n\n\n", "\n\n")
        return cleaned
