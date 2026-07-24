import os
import json
from typing import Any, Dict, List, Set

from core.datasets.loader import DatasetLoader

class DatasetPreprocessor:
    """
    Extracted from modules/dataset_preprocessing.py.
    Orchestrates the offline pipeline: loads datasets, deduplicates, and exports to canonical training formats.
    """

    def __init__(self, root_dir: str, knowledge_dir: str, data_dir: str):
        self.data_dir = data_dir
        self.loader = DatasetLoader(root_dir, knowledge_dir)

    def run_preprocessing_pipeline(self, extra_records: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute full normalization, deduplication, and export of training JSONL."""
        print("[DatasetPreprocessor] Starting dataset preprocessing pipeline...")
        records: List[Dict[str, Any]] = []
        records.extend(self.loader.load_juliet())
        records.extend(self.loader.load_code_samples())
        
        if extra_records:
            records.extend(extra_records)

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

        print(f"[DatasetPreprocessor] Successfully preprocessed and wrote {count} records to {merged_path}.")
        return {
            "total_raw": len(records),
            "unique_records": len(unique_records),
            "output_path": merged_path,
        }
