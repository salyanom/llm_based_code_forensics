Dataset guidance for fine-tuning the project's local LLM

Overview
- This project focuses on code forensics and security analysis. Fine-tuning data should reflect the assistant tasks: finding vulnerabilities, explaining their root cause, and proposing minimal patches.

Recommended dataset format
- JSONL with one object per line.
- Each object: {"prompt": "...", "completion": "...", "meta": {...}}
- Prompt: a clear instruction + the code to analyze (wrap codeblocks with triple backticks). Example prompt:
  "Analyze the following C function for security vulnerabilities and return a JSON object with keys: vulnerabilities, suggested_patch. Code: ```...```"
- Completion: the desired model response (ideally JSON for structured outputs) or a natural-language answer.

Sources to include (project-aligned)
- `code_samples/`: real sample files in this repo — great source of prompts.
- `knowledge/juliet.json`: Juliet test cases (already in repo) — convert into Q/A pairs.
- NVD/CVE descriptions in `knowledge/nvd.json` and `knowledge/owasp.json` for mapping vulnerability descriptions to remediation guidance.
- Manually labeled scans produced by `scan-pretty.ps1` or agent outputs in `agents/` — convert high-quality assistant replies into completions.

Practical process
1) Automated candidate assembly
   - Run `python scripts/prepare_dataset.py` to produce `data/dataset_candidates.jsonl`.
   - This file contains templated prompts and placeholder completions; these MUST be reviewed and labeled by a human.
2) Merge and normalize everything into one file
   - Run `python scripts/merge_datasets.py` to combine `data/dataset_candidates.jsonl`, `data/rag_export.jsonl`, and `data/rag_export_labeled.jsonl` into `data/merged_dataset.jsonl`.
   - The script normalizes line endings and whitespace, deduplicates by prompt, and preserves source provenance in `meta.source_files`.
3) Human labeling / validation
   - Open `data/dataset_candidates.jsonl`, fill `completion` with the correct JSON/natural-language answer for each prompt.
   - Ensure labels are concise, consistent, and include CWE tags when applicable.
4) Token counting and sizing
   - Install `transformers` in your venv and run:

```powershell
pip install transformers
python scripts/token_count.py --model YOUR_MODEL_ID --input data/dataset_candidates.jsonl
```

   - Review `data/token_counts.json` for total tokens. Use this to estimate training time.
4) Splits and sizes
   - Typical split: 90% train / 5% validation / 5% test.
   - For useful fine-tunes on code-assistant tasks: start with 5k–50k labeled examples for decent improvements (LoRA). More examples improve coverage.

Fine-tune method recommendation
- Use LoRA (parameter-efficient fine-tuning) on your RTX 4500 (24GB VRAM). It’s fast and fits the GPU.
- For LoRA, recommended starting hyperparams:
  - epochs: 3
  - micro_batch_size: 4
  - seq_length: 512–1024 (truncate long code or split into functions)
  - learning_rate: 1e-4 – 3e-4
- To train from the merged file, run `python scripts/train_lora.py --input data/merged_dataset.jsonl`.

Next steps (concrete)
- Run `python scripts/prepare_dataset.py`.
- Do a single-human-pass labeling of `data/dataset_candidates.jsonl` (or a 5k-sample subset).
- Run token counting with `scripts/token_count.py` (provide model tokenizer id).
- Tell me when you have the labeled dataset (or a sample) and I will run a micro-benchmark LoRA training on the workstation and return an ETA.

Licensing & privacy
- Avoid including proprietary code you cannot share.
- Check NVD/CVE and Juliet licensing (they are public) before redistribution.

Contact
- If you want, I can: run the candidate assembly, run token counting (you must confirm model id), and perform a LoRA micro-benchmark to estimate full fine-tune time.
