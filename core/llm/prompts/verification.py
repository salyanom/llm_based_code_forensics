import json
from typing import Any, Dict, Optional

DEFAULT_SYSTEM_PROMPT = (
    "You are an expert AI Secure Code Forensics engine powered by fine-tuned LoRA weights and RAG threat intelligence. "
    "Analyze the provided Abstract Syntax Tree (AST) code snippet and retrieved security knowledge. "
    "Output ONLY a valid JSON object with exact keys: 'is_vulnerable' (boolean), 'vulnerability_type' (string/CWE), "
    "'cve' (string), 'cvss_severity' ('Critical'|'High'|'Medium'|'Low'|'Info'), 'confidence' (integer 0-100), "
    "'explanation' (string explaining root cause), 'attack_vector' (string explaining exploitation), and 'suggested_patch' (string)."
)

def _estimate_tokens(text: str) -> int:
    return len(text) // 4 + 1

def _truncate_code(code: str, max_tokens: int) -> str:
    if _estimate_tokens(code) <= max_tokens:
        return code
    max_chars = max_tokens * 4
    half = max_chars // 2
    return code[:half] + "\n... [CODE TRUNCATED FOR TOKEN BUDGET] ...\n" + code[-half:]

def build_verification_prompt(
    ast_candidate: Dict[str, Any],
    rag_context: Dict[str, Any],
    lang_id: str,
    max_input_tokens: int = 3500,
    custom_system_prompt: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct a structured, token-budgeted prompt for vulnerability verification."""
    system_prompt = custom_system_prompt or DEFAULT_SYSTEM_PROMPT

    func_name = ast_candidate.get("function_name", "unknown")
    start_line = ast_candidate.get("start_line", 1)
    end_line = ast_candidate.get("end_line", 1)
    snippet = ast_candidate.get("snippet", "")
    candidates = ast_candidate.get("taint_candidates", [])

    sys_tokens = _estimate_tokens(system_prompt)
    rag_tokens_budget = min(1200, (max_input_tokens - sys_tokens) // 3)
    code_tokens_budget = max_input_tokens - sys_tokens - rag_tokens_budget - 200

    rag_cwe = rag_context.get("cwe", "Unknown")
    rag_cve = rag_context.get("cve", "Unknown")
    rag_rec = rag_context.get("owasp_recommendation", "")
    rag_refs = ", ".join(rag_context.get("references", []))
    rag_example = rag_context.get("vulnerable_example", "")
    if rag_example:
        rag_example = _truncate_code(rag_example, 300)

    rag_block = (
        f"=== RETRIEVED THREAT INTELLIGENCE (RAG) ===\n"
        f"Matching CWE: {rag_cwe} | Matching CVE: {rag_cve}\n"
        f"OWASP Recommendation: {rag_rec}\n"
        f"Reference Sources: {rag_refs}\n"
    )
    if rag_example:
        rag_block += f"Example Vulnerable Pattern:\n{rag_example}\n"

    rag_block = _truncate_code(rag_block, rag_tokens_budget)

    code_block = _truncate_code(snippet, code_tokens_budget)
    ast_summary = (
        f"=== AST TARGET CONTEXT ===\n"
        f"Language: {lang_id}\n"
        f"Function: {func_name} (Lines {start_line}-{end_line})\n"
        f"Detected Taint Candidates: {json.dumps(candidates)}\n\n"
        f"Source Code Snippet:\n```\n{code_block}\n```"
    )

    user_prompt = f"{rag_block}\n\n{ast_summary}\n\nProvide the JSON analysis response now."

    return {
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "full_prompt": f"### System:\n{system_prompt}\n\n### Instruction:\n{user_prompt}\n\n### Response:\n",
        "estimated_tokens": sys_tokens + _estimate_tokens(user_prompt),
    }
