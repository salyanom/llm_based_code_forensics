from typing import Any, Dict, List, Set

from core.knowledge.threat.loader import ThreatLoader

class ThreatPreprocessor:
    """
    Extracted from modules/dataset_preprocessing.py.
    Orchestrates loading and deduplicating of threat intelligence feeds (NVD, OWASP, etc.).
    """

    def __init__(self, knowledge_dir: str):
        self.loader = ThreatLoader(knowledge_dir)

    def load_and_preprocess(self) -> List[Dict[str, Any]]:
        """Load and deduplicate threat intelligence records."""
        records: List[Dict[str, Any]] = []
        records.extend(self.loader.load_owasp())
        records.extend(self.loader.load_nvd())

        # Deduplicate based on content hash
        seen_hashes: Set[str] = set()
        unique_records: List[Dict[str, Any]] = []
        for rec in records:
            h = rec["content_hash"]
            if h not in seen_hashes:
                seen_hashes.add(h)
                unique_records.append(rec)

        return unique_records
