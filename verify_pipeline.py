#!/usr/bin/env python3
"""
End-to-End Verification Script for Secure Code Forensics IDE
Runs each stage independently with file1.c and prints exact outputs.
"""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TARGET_FILE = os.path.join(os.path.dirname(__file__), "code_samples", "file1.c")

results = {}

# ── STAGE 1: Parser ──────────────────────────────────────────────────────────
print("\n" + "="*70)
print("STAGE 1: AST PARSER")
print("="*70)
try:
    from modules.parser import ASTParserModule
    parser = ASTParserModule()
    scan = parser.scan_file_incremental(TARGET_FILE, force_reparse=True)
    funcs = scan.get("functions", [])
    print(f"Language detected : {scan.get('language')}")
    print(f"Functions found   : {len(funcs)}")
    print(f"Imports found     : {scan.get('imports', [])}")
    print(f"Calls found       : {scan.get('calls', [])}")
    for fn in funcs:
        print(f"\n  Function: {fn['function_name']} (lines {fn['start_line']}-{fn['end_line']})")
        cands = fn.get("taint_candidates", [])
        print(f"  Taint candidates: {len(cands)}")
        for c in cands:
            print(f"    SINK: {c['sink']} | Line: {c['line_number']} | Text: {c['line_text']}")
            print(f"    Sources in scope: {c['sources_in_scope']} | Sanitized: {c['is_sanitized']}")
    results["stage1_ok"] = True
    results["parser_out"] = scan
except Exception as e:
    print(f"STAGE 1 FAILED: {e}")
    results["stage1_ok"] = False

# ── STAGE 2: RAG ─────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("STAGE 2: RAG VECTOR SEARCH")
print("="*70)
try:
    from modules.rag import RAGRetrievalModule
    rag = RAGRetrievalModule()
    test_candidate = {"sink": "gets", "line_text": "gets(user_input);", "sources_in_scope": []}
    rag_result = rag.retrieve_for_ast_candidate(test_candidate, "c")
    print(f"Query         : {rag_result['query']}")
    print(f"Retrieved CWE : {rag_result['cwe']}")
    print(f"Retrieved CVE : {rag_result['cve']}")
    print(f"OWASP Rec     : {rag_result['owasp_recommendation'][:120]}...")
    print(f"References    : {rag_result['references']}")
    print(f"\nTop matches (with similarity scores):")
    for m in rag_result.get("top_matches", []):
        print(f"  Score={m.get('similarity_score'):.4f}  Source={m.get('source')}  CWE={m.get('cwe')}  Title={m.get('title')}")
    results["stage2_ok"] = True
    results["rag_out"] = rag_result
except Exception as e:
    print(f"STAGE 2 FAILED: {e}")
    import traceback; traceback.print_exc()
    results["stage2_ok"] = False

# ── STAGE 3: Correlation ─────────────────────────────────────────────────────
print("\n" + "="*70)
print("STAGE 3: CORRELATION (AST -> RAG)")
print("="*70)
try:
    from modules.correlation import CorrelationModule
    corr_mod = CorrelationModule()
    if results.get("stage1_ok"):
        correlated = corr_mod.correlate_file_findings(TARGET_FILE, "c", results["parser_out"])
        print(f"Correlated findings: {len(correlated)}")
        for i, c in enumerate(correlated):
            print(f"\n  [{i+1}] Function={c['function_name']} Sink={c['sink']} Line={c['start_line']}")
            print(f"       RAG CWE={c['rag_context'].get('cwe')} CVE={c['rag_context'].get('cve')}")
        results["stage3_ok"] = True
        results["corr_out"] = correlated
    else:
        print("SKIPPED (Stage 1 failed)")
        results["stage3_ok"] = False
except Exception as e:
    print(f"STAGE 3 FAILED: {e}")
    import traceback; traceback.print_exc()
    results["stage3_ok"] = False

# ── STAGE 4: LLM Connection Check ────────────────────────────────────────────
print("\n" + "="*70)
print("STAGE 4: LLM ENGINE (Connection + Prompt Preview)")
print("="*70)
try:
    from modules.llm_engine import LLMEngine, LLMBackendOfflineError
    from modules.prompt_builder import PromptBuilderModule
    pb = PromptBuilderModule()
    llm = LLMEngine(pb)
    conn = llm.check_connection()
    print(f"LLM Status  : {conn.get('status')}")
    print(f"Provider    : {conn.get('provider')}")
    print(f"Endpoint    : {conn.get('endpoint', 'N/A')}")
    print(f"Error       : {conn.get('error', 'None')}")

    # Show what the prompt WOULD look like
    if results.get("stage3_ok") and results["corr_out"]:
        first_corr = results["corr_out"][0]
        prompt = pb.build_verification_prompt(first_corr, first_corr.get("rag_context", {}), "c")
        print(f"\n--- PROMPT SYSTEM (first 400 chars) ---")
        print(prompt["system_prompt"][:400])
        print(f"\n--- PROMPT USER (first 600 chars) ---")
        print(prompt["user_prompt"][:600])
        print(f"\nEstimated tokens: {prompt['estimated_tokens']}")
        results["prompt_preview"] = prompt

    results["stage4_ok"] = True
    results["llm_online"] = conn.get("status") == "ONLINE"
except Exception as e:
    print(f"STAGE 4 FAILED: {e}")
    results["stage4_ok"] = False
    results["llm_online"] = False

# ── STAGE 5: Verification ────────────────────────────────────────────────────
print("\n" + "="*70)
print("STAGE 5: VERIFICATION (CVSS + Confidence)")
print("="*70)
try:
    from modules.verification import VerificationModule
    ver = VerificationModule()
    if results.get("stage3_ok") and results["corr_out"]:
        verified_all = []
        for corr in results["corr_out"]:
            v = ver.verify_finding(corr, {})   # offline → no LLM response
            verified_all.append(v)
            print(f"  Sink={v['sink']} CWE={v['cwe']} Severity={v['severity']} CVSS={v['cvss_score']} Confidence={v['confidence']}%")
            print(f"  CVSS Vector: {v['cvss_vector']}")
        results["stage5_ok"] = True
        results["verified_out"] = verified_all
    else:
        print("SKIPPED (Stage 3 failed)")
        results["stage5_ok"] = False
except Exception as e:
    print(f"STAGE 5 FAILED: {e}")
    results["stage5_ok"] = False

# ── STAGE 6: Explainability ──────────────────────────────────────────────────
print("\n" + "="*70)
print("STAGE 6: EXPLAINABILITY")
print("="*70)
try:
    from modules.explainability import ExplainabilityModule
    exp_mod = ExplainabilityModule()
    if results.get("stage5_ok") and results["verified_out"]:
        first_v = results["verified_out"][0]
        exp = exp_mod.generate_evidence_explanation(first_v)
        print(f"Why:\n  {exp['why'][:300]}")
        print(f"CWE:\n  {exp['supporting_cwe'][:200]}")
        print(f"CVE:\n  {exp['supporting_cve'][:200]}")
        print(f"OWASP:\n  {exp['owasp_recommendation'][:200]}")
        print(f"References:\n  {exp['references']}")
        print(f"\nmarkdown_report present: {'YES' if exp.get('markdown_report') else 'NO'}")
        print(f"markdown_report length: {len(exp.get('markdown_report',''))} chars")
        results["stage6_ok"] = True
        results["explain_out"] = exp
    else:
        print("SKIPPED")
        results["stage6_ok"] = False
except Exception as e:
    print(f"STAGE 6 FAILED: {e}")
    results["stage6_ok"] = False

# ── STAGE 7: Patch Generation ────────────────────────────────────────────────
print("\n" + "="*70)
print("STAGE 7: PATCH GENERATION")
print("="*70)
try:
    from modules.patch_generation import PatchGenerationModule
    patch_mod = PatchGenerationModule()
    if results.get("stage5_ok") and results["verified_out"]:
        for v in results["verified_out"]:
            patch = patch_mod.generate_patch_for_finding(v)
            print(f"  Sink={v['sink']}")
            print(f"  Is heuristic: {patch['is_heuristic']}")
            print(f"  Is valid: {patch['is_valid']}")
            print(f"  Validation: {patch['validation_message']}")
            diff = patch.get("unified_diff", "")
            if diff:
                print(f"  Diff (first 500 chars):\n{diff[:500]}")
            else:
                print("  WARNING: unified_diff is EMPTY")
            print()
        results["stage7_ok"] = True
        results["patch_out"] = patch
    else:
        print("SKIPPED")
        results["stage7_ok"] = False
except Exception as e:
    print(f"STAGE 7 FAILED: {e}")
    import traceback; traceback.print_exc()
    results["stage7_ok"] = False

# ── STAGE 8: Persistence ─────────────────────────────────────────────────────
print("\n" + "="*70)
print("STAGE 8: SQLITE PERSISTENCE")
print("="*70)
try:
    from modules.persistence import PersistenceModule
    import tempfile
    tmp_db = os.path.join(os.path.dirname(__file__), "tests_tmp_db", "verify_test.db")
    os.makedirs(os.path.dirname(tmp_db), exist_ok=True)
    pm = PersistenceModule(db_path=tmp_db)
    proj_id = pm.register_or_get_project("/tmp/test_project")
    scan_id = pm.create_scan_run(proj_id, file_count=1, findings_count=0)
    print(f"Project ID: {proj_id}")
    print(f"Scan ID: {scan_id}")

    if results.get("stage5_ok") and results["verified_out"]:
        # Attach explanation and patch to each finding
        for i, v in enumerate(results["verified_out"]):
            if results.get("stage6_ok"):
                v["explanation_json"] = results.get("explain_out", {})
            if results.get("stage7_ok"):
                patch = patch_mod.generate_patch_for_finding(v) if results.get("stage7_ok") else {}
                v["patch_diff"] = patch.get("unified_diff", "")
                v["patched_snippet"] = patch.get("patched_snippet", "")
        saved = pm.save_vulnerabilities(scan_id, results["verified_out"])
        pm.update_scan_findings_count(scan_id, saved)
        print(f"Saved {saved} vulnerability records to SQLite")
        loaded = pm.get_scan_vulnerabilities(scan_id)
        print(f"Reloaded {len(loaded)} records from SQLite")
        if loaded:
            first = loaded[0]
            print(f"  Record: sink={first.get('sink')} cwe={first.get('cwe')} severity={first.get('severity')} confidence={first.get('confidence')}")
            print(f"  patch_diff present: {'YES' if first.get('patch_diff') else 'NO'}")
            print(f"  explanation_json present: {'YES' if first.get('explanation_json') else 'NO'}")
    results["stage8_ok"] = True
except Exception as e:
    print(f"STAGE 8 FAILED: {e}")
    import traceback; traceback.print_exc()
    results["stage8_ok"] = False

# ── SUMMARY ──────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("VERIFICATION SUMMARY")
print("="*70)
stages = [
    ("Stage 1 – AST Parser",         results.get("stage1_ok")),
    ("Stage 2 – RAG Vector Search",   results.get("stage2_ok")),
    ("Stage 3 – Correlation",         results.get("stage3_ok")),
    ("Stage 4 – LLM Engine",          results.get("stage4_ok")),
    ("Stage 5 – Verification/CVSS",   results.get("stage5_ok")),
    ("Stage 6 – Explainability",      results.get("stage6_ok")),
    ("Stage 7 – Patch Generation",    results.get("stage7_ok")),
    ("Stage 8 – SQLite Persistence",  results.get("stage8_ok")),
]
for name, ok in stages:
    status = "PASS" if ok else "FAIL"
    print(f"  {status:4}  {name}")
print(f"\nLLM Backend: {'ONLINE' if results.get('llm_online') else 'OFFLINE'}")
print("="*70)
