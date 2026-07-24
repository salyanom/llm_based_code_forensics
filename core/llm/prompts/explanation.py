from typing import Any, Dict, List, Optional
from core.llm.prompts.verification import _estimate_tokens, _truncate_code

def build_chat_prompt(
    question: str,
    active_code: str,
    lang_id: str,
    rag_context: Dict[str, Any],
    history: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """Construct grounded prompt for interactive AI Chat questions."""
    system_prompt = (
        "You are an AI Security Assistant pair programming with the user inside the Secure Code Forensics IDE. "
        "Answer the user's question clearly, concisely, and accurately using the provided code snippet and RAG threat intelligence context. "
        "If code rewrite or patch advice is requested, format code cleanly in markdown."
    )

    code_block = _truncate_code(active_code, 1500)
    rag_rec = rag_context.get("owasp_recommendation", "")
    cwe = rag_context.get("cwe", "Unknown")

    context_header = (
        f"[Grounded Context] Language: {lang_id} | Target CWE: {cwe}\n"
        f"[Threat Advice] {rag_rec}\n"
        f"[Active File Snippet]\n```\n{code_block}\n```\n"
    )

    if history:
        hist_str = "\n".join(f"User: {h.get('user', '')}\nAI: {h.get('ai', '')}" for h in history[-3:])
        context_header += f"\n[Recent Conversation]\n{hist_str}\n"

    user_prompt = f"{context_header}\nUser Question: {question}\n\nAI Answer:"

    return {
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "full_prompt": f"### System:\n{system_prompt}\n\n### Instruction:\n{user_prompt}\n",
        "estimated_tokens": _estimate_tokens(system_prompt + user_prompt),
    }
