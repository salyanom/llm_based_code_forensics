"""Prepare candidate fine-tuning examples from project artifacts.

Produces JSONL files under `data/`:
- `dataset_candidates.jsonl` — automatically assembled candidate examples for human review/labeling.

Usage:
    python scripts/prepare_dataset.py

The script scans `code_samples/`, `tree-sitter-c/examples` and `knowledge/juliet.json` (if present)
and emits instructive prompt/completion templates suitable for an instruction-following fine-tune dataset.
"""

import os
import json
from glob import glob

ROOT = os.path.dirname(os.path.dirname(__file__))

CODE_DIRS = [
    os.path.join(ROOT, "code_samples"),
    os.path.join(ROOT, "tree-sitter-c", "examples"),
]

OUT_DIR = os.path.join(ROOT, "data")
os.makedirs(OUT_DIR, exist_ok=True)


def make_code_example(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read().strip()
    prompt = f"""Analyze the following source code for security vulnerabilities and return a JSON object with keys:
- vulnerabilities: list of {{location, type, description}}
- suggested_patch: short patch or remediation steps

Code:

{code}


Please respond only with the JSON object.
"""

    completion = {
        "vulnerabilities": [],
        "suggested_patch": ""
    }

    return {
        "prompt": prompt,
        "completion": completion,
        "meta": {"source": path}
    }

def make_juliet_examples(juliet_path):
    examples = []

    try:
        with open(juliet_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return examples

    records = data if isinstance(data, list) else [data]

    for item in records:
        title = item.get("title") or item.get("id") or "juliet_case"
        desc = item.get("description") or item.get("summary") or ""
        code = item.get("code") or item.get("source") or item.get("snippet") or ""
        prompt = f"""The Juliet test case '{title}' describes a vulnerability.

Description:
{desc}

Analyze the code and provide:
1. Vulnerability type (CWE if known)
2. Short explanation
3. Minimal patch or mitigation

Respond as JSON.

Code:

{code}

"""

        completion = {
            "cwe": "",
            "explanation": "",
            "patch": ""
        }

        examples.append(
            {
                "prompt": prompt,
                "completion": completion,
                "meta": {
                    "source": juliet_path,
                    "case": title
                }
            }
        )

    return examples


def gather():
    out_path = os.path.join(OUT_DIR, "dataset_candidates.jsonl")
    written = 0

    with open(out_path, "w", encoding="utf-8") as out:

        for codedir in CODE_DIRS:
            for ext in ("*.c", "*.cpp", "*.py", "*.js", "*.java"):
                for path in glob(os.path.join(codedir, "**", ext), recursive=True):
                    try:
                        ex = make_code_example(path)
                        out.write(json.dumps(ex, ensure_ascii=False) + "\n")
                        written += 1
                    except Exception:
                        continue

        juliet = os.path.join(ROOT, "knowledge", "juliet.json")

        if os.path.exists(juliet):
            for ex in make_juliet_examples(juliet):
                out.write(json.dumps(ex, ensure_ascii=False) + "\n")
                written += 1

    print(f"Wrote {written} candidate examples to {out_path}")


if __name__ == "__main__":
    gather()