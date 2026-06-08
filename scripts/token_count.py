"""Compute token counts for a dataset JSONL using a tokenizer.

Usage:
    python scripts/token_count.py --model MODEL_ID --input data/dataset_candidates.jsonl

Writes `data/token_counts.json` with summary and per-example token counts.
"""
import argparse
import json
import os
from transformers import AutoTokenizer

parser = argparse.ArgumentParser()
parser.add_argument("--model", required=True, help="Hugging Face model id or local tokenizer path")
parser.add_argument("--input", required=True, help="JSONL input file with `prompt` and optional `completion` fields")
args = parser.parse_args()

tokenizer = AutoTokenizer.from_pretrained(args.model, use_fast=True)

out = {"total_examples": 0, "total_tokens": 0, "examples": []}

with open(args.input, "r", encoding="utf-8") as f:
    for line in f:
        obj = json.loads(line)
        text = obj.get("prompt", "") + "\n" + obj.get("completion", "")
        toks = tokenizer(text, return_attention_mask=False, add_special_tokens=True)
        ct = len(toks["input_ids"])
        out["examples"].append({"meta": obj.get("meta"), "tokens": ct})
        out["total_examples"] += 1
        out["total_tokens"] += ct

os.makedirs(os.path.dirname(args.input), exist_ok=True)
with open(os.path.join(os.path.dirname(args.input), "token_counts.json"), "w", encoding="utf-8") as wf:
    json.dump(out, wf, indent=2)

print(f"Processed {out['total_examples']} examples, total tokens: {out['total_tokens']}")
