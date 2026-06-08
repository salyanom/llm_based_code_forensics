import json
import ollama
from pathlib import Path

INPUT = "data/rag_export.jsonl"
OUTPUT = "data/rag_export_labeled.jsonl"

MODEL = "deepseek-coder:6.7b"

with open(INPUT, "r", encoding="utf-8") as fin, \
     open(OUTPUT, "w", encoding="utf-8") as fout:

    for i, line in enumerate(fin, start=1):
        row = json.loads(line)

        prompt = row["prompt"]

        response = ollama.chat(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity expert. "
                        "Generate high-quality training completions."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            options={"temperature": 0.1},
        )

        row["completion"] = response["message"]["content"]

        fout.write(json.dumps(row, ensure_ascii=False) + "\n")

        print(f"{i} done")