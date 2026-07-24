from typing import Any, Dict

class ExplainabilityAgent:
    """Evidence-Based Explainability Engine formatting Why -> CWE -> CVE -> PrimeVul -> OWASP -> References."""

    def generate_evidence_explanation(self, verified_finding: Dict[str, Any]) -> Dict[str, Any]:
        """Produce rich structured evidence breakdown grounded in AST data and RAG context."""
        corr = verified_finding.get("correlated_item", {})
        rag_ctx = corr.get("rag_context", {})
        llm_resp = verified_finding.get("llm_response", {})

        cwe = verified_finding.get("cwe", "Unknown")
        cve = verified_finding.get("cve", "Unknown")
        sink = verified_finding.get("sink", "unknown_sink")
        line_text = verified_finding.get("line_text", "")
        func_name = verified_finding.get("function_name", "unknown")
        sources = corr.get("sources_in_scope", [])

        llm_why = ""
        if isinstance(llm_resp, dict):
            llm_why = llm_resp.get("explanation") or llm_resp.get("why") or llm_resp.get("root_cause") or ""
        if llm_why:
            why_text = f"{llm_why}\n\nAST Trace: In function '{func_name}', untrusted data reaching '{sink}' at line {verified_finding.get('start_line')}: `{line_text}`"
        else:
            if sources:
                why_text = (
                    f"Untrusted input from source(s) `{', '.join(sources)}` enters function `{func_name}` and flows directly into dangerous sink `{sink}` "
                    f"at line {verified_finding.get('start_line')} without sufficient validation or bounds checks: `{line_text}`."
                )
            else:
                why_text = (
                    f"Dangerous sink function `{sink}` invoked in `{func_name}` at line {verified_finding.get('start_line')}: `{line_text}`. "
                    f"If user-controlled or unbounded data reaches this call, it triggers severe memory corruption or execution vulnerabilities."
                )

        cwe_desc = f"Official Classification: {cwe}. Memory corruption or injection failure due to improper boundary or syntax validation."
        if isinstance(llm_resp, dict) and llm_resp.get("cwe_description"):
            cwe_desc = f"{cwe}: {llm_resp['cwe_description']}"
        else:
            for m in rag_ctx.get("top_matches", []):
                if m.get("cwe") == cwe and m.get("description"):
                    cwe_desc = f"{cwe}: {m['description']}"
                    break

        cve_desc = f"Associated CVE Reference: {cve}."
        if cve != "Unknown":
            for m in rag_ctx.get("top_matches", []):
                if m.get("cve") == cve and m.get("description"):
                    cve_desc = f"{cve}: {m['description']}"
                    break

        primevul_example = rag_ctx.get("vulnerable_example", "")
        if not primevul_example:
            primevul_example = f"// Similar insecure usage of {sink}\nchar buffer[64];\n{sink}(buffer, untrusted_input); // Unbounded copy"

        owasp_rec = ""
        if isinstance(llm_resp, dict):
            owasp_rec = llm_resp.get("owasp_recommendation") or llm_resp.get("remediation") or llm_resp.get("recommendation") or ""
        if not owasp_rec:
            owasp_rec = rag_ctx.get("owasp_recommendation", "")
        if not owasp_rec:
            owasp_rec = f"Never pass unvalidated or unbounded strings to `{sink}`. Use bounded alternatives (such as `strncpy` or `snprintf`) and enforce strict boundary checks."

        references = rag_ctx.get("references", [])
        if isinstance(llm_resp, dict) and isinstance(llm_resp.get("references"), list) and llm_resp.get("references"):
            references = list(set(references + llm_resp["references"]))
        if not references:
            references = [f"OWASP Secure Coding Practices ({cwe})", f"CWE Dictionary Entry for {cwe}"]

        structured = {
            "why": why_text,
            "supporting_cwe": cwe_desc,
            "supporting_cve": cve_desc,
            "primevul_example": primevul_example,
            "owasp_recommendation": owasp_rec,
            "references": references,
        }

        md_report = (
            f"### [Root Cause Analysis - Why]\n{why_text}\n\n"
            f"### [Supporting CWE Classification]\n**{cwe}**: {cwe_desc}\n\n"
            f"### [Supporting CVE Intelligence]\n**{cve}**: {cve_desc}\n\n"
            f"### [Vulnerable Code Example - PrimeVul/Dataset]\n```c\n{primevul_example}\n```\n\n"
            f"### [OWASP Remediation Recommendation]\n{owasp_rec}\n\n"
            f"### [References & Threat Citations]\n" + "\n".join(f"- {r}" for r in references)
        )

        structured["markdown_report"] = md_report
        return structured
