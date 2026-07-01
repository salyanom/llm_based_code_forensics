"""Normalize and merge dataset JSONL files into one canonical dataset.

The script combines the project's dataset sources into a single JSONL file for the
next stage of labeling or training:

- `data/dataset_candidates.jsonl`
- `data/rag_export.jsonl`
- `data/rag_export_labeled.jsonl`

Normalization steps:
- convert CRLF/CR line endings to LF
- trim outer whitespace
- strip trailing whitespace on each line
- collapse runs of 3+ blank lines to 2
- standardize `meta` into a dictionary and preserve source provenance

By default the merged output keeps rows even if `completion` is empty, which is
useful for the review/labeling stage. Pass `--require-completion` to emit only
training-ready rows.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Tuple


ROOT = os.path.dirname(os.path.dirname(__file__))
DEFAULT_INPUTS = [
    os.path.join(ROOT, "data", "dataset_candidates.jsonl"),
    os.path.join(ROOT, "data", "rag_export.jsonl"),
    os.path.join(ROOT, "data", "rag_export_labeled.jsonl"),
]
DEFAULT_OUTPUT = os.path.join(ROOT, "data", "merged_dataset.jsonl")


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    text = "\n".join(lines).strip()

    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")

    return text


def _normalize_meta(meta: Any) -> Dict[str, Any]:
    if isinstance(meta, dict):
        return dict(meta)
    if meta is None:
        return {}
    return {"value": meta}


def _source_kind(path: str) -> str:
    base = os.path.basename(path).lower()
    if "candidate" in base:
        return "candidate"
    if "labeled" in base:
        return "labeled"
    if "rag_export" in base:
        return "rag_export"
    return os.path.splitext(base)[0]


def _read_jsonl(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            if isinstance(row, dict):
                yield row


def _merge_records(records: Iterable[Tuple[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
    merged: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()

    for path, row in records:
        prompt = _normalize_text(row.get("prompt"))
        completion = _normalize_text(row.get("completion"))

        if not prompt:
            continue

        meta = _normalize_meta(row.get("meta"))
        source_files = meta.get("source_files")
        if not isinstance(source_files, list):
            source_files = []

        source_file = os.path.relpath(path, ROOT).replace("\\", "/")
        source_files.append(source_file)

        meta["source_files"] = sorted({str(item) for item in source_files if str(item).strip()})
        meta["source_kind"] = _source_kind(path)
        meta["normalized"] = True

        completion_exists = bool(completion.strip())
        score = 0
        if completion_exists:
            score += 2
        if meta["source_kind"] == "labeled":
            score += 2
        if meta["source_kind"] == "candidate":
            score += 1

        current = merged.get(prompt)
        candidate = {
            "prompt": prompt,
            "completion": completion,
            "meta": meta,
            "_score": score,
        }

        if current is None:
            merged[prompt] = candidate
            continue

        current_sources = current.setdefault("meta", {}).setdefault("source_files", [])
        if source_file not in current_sources:
            current_sources.append(source_file)
            current["meta"]["source_files"] = sorted({str(item) for item in current_sources if str(item).strip()})

        current_score = current.get("_score", 0)
        current_completion = current.get("completion", "")
        if score > current_score or (score == current_score and len(completion) > len(current_completion)):
            merged[prompt] = candidate

    output: List[Dict[str, Any]] = []
    for row in merged.values():
        row.pop("_score", None)
        output.append(row)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize and merge dataset JSONL files.")
    parser.add_argument(
        "--input",
        action="append",
        dest="inputs",
        help="Additional JSONL input file to merge. Can be passed multiple times.",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Merged output file (default: {os.path.relpath(DEFAULT_OUTPUT, ROOT)})",
    )
    parser.add_argument(
        "--require-completion",
        action="store_true",
        help="Only keep rows with a non-empty completion.",
    )
    args = parser.parse_args()

    input_paths: List[str] = []
    for path in DEFAULT_INPUTS + (args.inputs or []):
        if not path:
            continue
        if os.path.exists(path) and path not in input_paths:
            input_paths.append(path)

    if not input_paths:
        raise SystemExit("No input dataset files were found.")

    rows: List[Tuple[str, Dict[str, Any]]] = []
    for path in input_paths:
        for row in _read_jsonl(path):
            rows.append((path, row))

    merged_rows = _merge_records(rows)
    if args.require_completion:
        merged_rows = [row for row in merged_rows if _normalize_text(row.get("completion"))]

    output_path = args.output
    if not os.path.isabs(output_path):
        output_path = os.path.join(ROOT, output_path)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        for row in merged_rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"Merged {len(merged_rows)} rows into {output_path}")
    print("Inputs:")
    for path in input_paths:
        print(f"- {os.path.relpath(path, ROOT)}")


if __name__ == "__main__":
    main()