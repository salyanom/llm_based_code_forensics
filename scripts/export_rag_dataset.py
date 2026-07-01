"""Export RAG entries into a JSONL suitable for labeling/fine-tuning.

Writes `data/rag_export.jsonl` with objects:
  {"prompt":..., "meta": {...}, "source_entry": {...}}

Usage:
    python scripts/export_rag_dataset.py
    python scripts/export_rag_dataset.py --primevul

You can set environment variables to control behavior:
  RAG_EMBED_MODEL - sentence-transformers model id (default: all-MiniLM-L6-v2)
  RAG_MAX_PRIMEVUL_RECORDS - if set, limits how many PrimeVul records are loaded
"""
import argparse
import os
import sys
import json

# Ensure project root is on sys.path so `services` package imports work when running the script
ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from services.rag_engine import _preprocess_record

OUT_DIR = os.path.join(ROOT, "data")
os.makedirs(OUT_DIR, exist_ok=True)
OUT_PATH = os.path.join(OUT_DIR, "rag_export.jsonl")

def parse_args():
    parser = argparse.ArgumentParser(description="Export normalized dataset rows to JSONL.")
    parser.add_argument(
        "--primevul",
        action="store_true",
        help="Also export PrimeVul from Hugging Face using services.rag_engine.",
    )
    return parser.parse_args()

def load_local_knowledge():
    knowledge_dir = os.path.join(os.getcwd(), "knowledge")
    entries = []
    if not os.path.isdir(knowledge_dir):
        return entries

    for file_name in sorted(os.listdir(knowledge_dir)):
        if file_name == "nvd_live.json":
            continue
        if not (file_name.endswith(".json") or file_name.endswith(".jsonl")):
            continue

        path = os.path.join(knowledge_dir, file_name)
        try:
            if path.endswith(".jsonl"):
                with open(path, "r", encoding="utf-8") as handle:
                    for line in handle:
                        try:
                            row = json.loads(line)
                        except Exception:
                            continue
                        raw_text = row.get("embedding_text") or row.get("text") or row.get("description")
                        if not isinstance(raw_text, str) or not raw_text.strip():
                            continue
                        source = row.get("source", "Knowledge")
                        entry_type = row.get("type", "concept")
                        min_tokens = 10 if entry_type == "code" else 3
                        pre = _preprocess_record(
                            raw_text=raw_text,
                            cwe_raw=row.get("cwe"),
                            cve_raw=row.get("cve"),
                            source=source,
                            strip_comments=entry_type == "code",
                            min_tokens=min_tokens,
                            max_tokens=512,
                        )
                        if not pre:
                            continue
                        metadata = row.get("metadata", {}) if isinstance(row.get("metadata"), dict) else {}
                        extra = {k: v for k, v in row.items() if k not in {"source", "type", "embedding_text", "text", "description", "cwe", "cve", "metadata"}}
                        if extra:
                            metadata = {**metadata, **extra}
                        entries.append({
                            "source": source,
                            "type": entry_type,
                            "embedding_text": pre["embedding_text"],
                            "cwe": pre["cwe"],
                            "cve": pre["cve"],
                            "token_count": pre["token_count"],
                            "content_hash": pre["content_hash"],
                            "metadata": metadata,
                        })
                continue

            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)

            if isinstance(payload, list):
                seq = payload
            else:
                seq = [payload]

            for item in seq:
                raw_text = item.get("embedding_text") or item.get("text") or item.get("description")
                if not isinstance(raw_text, str) or not raw_text.strip():
                    continue
                source = item.get("source", "Knowledge")
                entry_type = item.get("type", "concept")
                min_tokens = 10 if entry_type == "code" else 3
                pre = _preprocess_record(
                    raw_text=raw_text,
                    cwe_raw=item.get("cwe"),
                    cve_raw=item.get("cve"),
                    source=source,
                    strip_comments=entry_type == "code",
                    min_tokens=min_tokens,
                    max_tokens=512,
                )
                if not pre:
                    continue
                metadata = item.get("metadata", {}) if isinstance(item.get("metadata"), dict) else {}
                extra = {k: v for k, v in item.items() if k not in {"source", "type", "embedding_text", "text", "description", "cwe", "cve", "metadata"}}
                if extra:
                    metadata = {**metadata, **extra}
                entries.append({
                    "source": source,
                    "type": entry_type,
                    "embedding_text": pre["embedding_text"],
                    "cwe": pre["cwe"],
                    "cve": pre["cve"],
                    "token_count": pre["token_count"],
                    "content_hash": pre["content_hash"],
                    "metadata": metadata,
                })
        except Exception as exc:
            print(f"[export] Skipping invalid knowledge file {file_name}: {exc}")
            continue

    return entries

args = parse_args()

entries = load_local_knowledge()
if args.primevul or os.getenv("RAG_EXPORT_PRIMEVUL", "0") == "1":
    # Attempt heavy export using RAGEngine (may download). Use only when explicitly requested.
    try:
        from services.rag_engine import RAGEngine
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer(os.getenv("RAG_EMBED_MODEL", "all-MiniLM-L6-v2"))
        engine = RAGEngine(model=model)
        entries.extend(engine._load_primevul())
    except Exception as exc:
        print(f"[export] PrimeVul export failed or skipped: {exc}")

print(f"Exporting {len(entries)} local RAG entries to {OUT_PATH}")
count = 0
with open(OUT_PATH, "w", encoding="utf-8") as out:
    for e in entries:
        # Build a labeled-friendly prompt depending on type
        etext = e.get("embedding_text", "")
        etype = e.get("type", "concept")
        cwe = e.get("cwe", "Unknown")
        cve = e.get("cve", "Unknown")

        if etype == "code":
            prompt = (
                "Analyze the following source code for security vulnerabilities and return a JSON object with keys:\n"
                "- vulnerabilities: list of {location, type, description}\n"
                "- suggested_patch: short patch or remediation steps\n\n"
                f"{etext}\n\nRespond only with the JSON object."
            )
        elif etype == "cve_description":
            prompt = (
                "Summarize the CVE description and recommend mitigations. Return a JSON object with keys:\n"
                "- summary: short summary\n- mitigations: list of steps\n\n"
                f"{etext}\n\nRespond only with the JSON object."
            )
        else:
            prompt = (
                "Read the following security knowledge item and produce a short actionable remediation or summary as JSON:\n"
                f"{etext}\n\nRespond only with JSON."
            )

        out_obj = {
            "prompt": prompt,
            "meta": {
                "source": e.get("source"),
                "type": etype,
                "cwe": cwe,
                "cve": cve,
                "token_count": e.get("token_count"),
            },
            "source_entry": e,
            "completion": ""  # labelers should fill this in
        }
        out.write(json.dumps(out_obj, ensure_ascii=False) + "\n")
        count += 1

print(f"Wrote {count} entries")
