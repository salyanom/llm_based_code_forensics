from __future__ import annotations

import json
import os
import tempfile
import threading
import uuid
import warnings
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    C_RED=Fore.RED; C_GREEN=Fore.GREEN; C_YELLOW=Fore.YELLOW; C_BLUE=Fore.BLUE
    C_CYAN=Fore.CYAN; C_MAGENTA=Fore.MAGENTA; C_WHITE=Fore.WHITE
    C_DIM=Style.DIM; C_RESET=Style.RESET_ALL; C_BRIGHT=Style.BRIGHT
except Exception:
    C_RED=C_GREEN=C_YELLOW=C_BLUE=C_CYAN=C_MAGENTA=C_WHITE=C_DIM=C_RESET=C_BRIGHT=""

from agents.correlation_agent import CorrelationAgent
from agents.detection_agent import DetectionAgent
from agents.patch_agent import PatchAgent
from agents.verification_agent import VerificationAgent
from database.models import ScanRepository
from services.llm_service import LLMService
from services.parser_service import ParserService
from services.rag_engine import RAGEngine

warnings.filterwarnings("ignore", category=FutureWarning, module="tree_sitter")
MODEL_NAME = "all-MiniLM-L6-v2"

DEFAULT_SCAN_ROOT = os.path.realpath(
    os.path.abspath(os.getenv("SCAN_ALLOWED_ROOT", os.path.join(os.getcwd(), "code_samples")))
)

_pipeline_instance: Optional["SecurityPipeline"] = None
_pipeline_lock = threading.Lock()


def _get_pipeline() -> "SecurityPipeline":
    global _pipeline_instance
    if _pipeline_instance is None:
        with _pipeline_lock:
            if _pipeline_instance is None:
                _pipeline_instance = SecurityPipeline()
    return _pipeline_instance


def _validate_scan_folder(folder: str) -> str:
    resolved = os.path.realpath(os.path.abspath(folder))
    allowed  = DEFAULT_SCAN_ROOT
    if resolved != allowed and not resolved.startswith(allowed + os.sep):
        raise HTTPException(status_code=400, detail=f"Folder '{folder}' is outside the allowed scan root: {allowed}")
    if not os.path.isdir(resolved):
        raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
    return resolved


class ScanRequest(BaseModel):
    folder: str = "code_samples"
    query:  str = "scan all"
    generate_patches: bool = True

class FeedbackRequest(BaseModel):
    scan_id: str
    vulnerability_id: Optional[int] = None
    is_false_positive: bool
    comment: str = ""

class AssistantAskRequest(BaseModel):
    prompt: str
    scan_id: Optional[str] = None
    top_findings: int = 5


class SecurityPipeline:
    def __init__(self):
        self.embedding_model    = SentenceTransformer(MODEL_NAME)
        self.parser_service     = ParserService()
        self.llm_service        = LLMService()
        self.rag_engine         = RAGEngine(self.embedding_model)
        self.repo               = ScanRepository(db_path="scan_sessions.db")
        self.detection_agent    = DetectionAgent(self.parser_service)
        self.correlation_agent  = CorrelationAgent(self.rag_engine)
        self.verification_agent = VerificationAgent(self.llm_service)
        self.patch_agent        = PatchAgent(self.llm_service, self.parser_service)

    def _build_structured_report(self, query, findings, generate_patches):
        vulnerabilities = []
        for finding in findings:
            rag_matches = self.correlation_agent.correlate(finding)
            verified    = self.verification_agent.verify(finding, rag_matches)
            for vuln in verified:
                record = {
                    "file": finding.get("file"), "function_name": finding.get("function_name"),
                    "language": finding.get("language"), "type": vuln.get("type"),
                    "severity": vuln.get("severity"), "line": vuln.get("line"),
                    "cwe": vuln.get("cwe"), "cve": vuln.get("cve"),
                    "cvss_score": vuln.get("cvss_score"), "cvss_vector": vuln.get("cvss_vector"),
                    "confidence": vuln.get("confidence", 0.0),
                    "threat_intel_match": vuln.get("threat_intel_match"),
                    "explanation": vuln.get("explanation"),
                }
                if generate_patches:
                    patched = self.patch_agent.generate_patch(finding.get("function", ""), record["type"])
                    pv      = self.patch_agent.verify_patch(finding.get("function",""), patched, language=finding.get("language","c"))
                    record["patch"] = patched; record["patch_verification"] = pv
                vulnerabilities.append(record)
        return {
            "scan_id": str(uuid.uuid4()), "created_at": datetime.utcnow().isoformat(),
            "query": query, "files_scanned": sorted({f.get("file","") for f in findings}),
            "vulnerabilities": vulnerabilities,
            "summary": {"total_functions": len(findings), "total_vulnerabilities": len(vulnerabilities)},
        }

    def run_scan(self, folder, query="scan all", generate_patches=True, verbose=False):
        if not os.path.isdir(folder):
            raise FileNotFoundError(f"Folder not found: {folder}")
        if verbose: print(f"{C_CYAN}[*] Parsing: {folder}{C_RESET}")
        findings = self.detection_agent.scan_folder(folder)
        if verbose: print(f"{C_CYAN}[*] Functions: {len(findings)}{C_RESET}")
        if not findings:
            return {"scan_id": str(uuid.uuid4()), "created_at": datetime.utcnow().isoformat(),
                    "query": query, "files_scanned": [], "vulnerabilities": [],
                    "summary": {"total_functions": 0, "total_vulnerabilities": 0}}
        if query.strip().lower() != "scan all":
            if verbose: print(f"{C_CYAN}[*] Semantic query mode{C_RESET}")
            qv   = self.embedding_model.encode([query])
            fv   = self.embedding_model.encode([f.get("function","") for f in findings])
            sims = (fv @ qv.T).reshape(-1)
            findings = [findings[int(sims.argmax())]]
        if verbose: print(f"{C_CYAN}[*] Correlating + verifying...{C_RESET}")
        report  = self._build_structured_report(query, findings, generate_patches)
        scan_id = self.repo.save_scan(query, report)
        report["scan_id"] = scan_id
        if verbose: print(f"{C_GREEN}[+] Done. scan_id={scan_id}{C_RESET}")
        return report

    def ask_assistant(self, prompt, scan_id=None, top_findings=5):
        selected = None
        if scan_id:
            selected = self.repo.get_scan(scan_id)
            if selected is None: raise ValueError(f"Scan not found: {scan_id}")
        else:
            recent = self.repo.list_scans(limit=1)
            if recent: selected = self.repo.get_scan(recent[0].get("scan_id",""))
        context = {}; rid = None
        if selected:
            vulns   = selected.get("vulnerabilities", [])
            context = {"scan_id": selected.get("scan_id"), "query": selected.get("query"),
                       "summary": selected.get("summary",{}), "files_scanned": selected.get("files_scanned",[]),
                       "top_findings": vulns[:max(1, top_findings)]}
            rid = selected.get("scan_id")
        answer = self.llm_service.ask_security_assistant(prompt=prompt, scan_context=context)
        return {"scan_id": rid, "answer": answer,
                "context_summary": {"files_scanned": len(context.get("files_scanned",[])),
                                    "findings_shared": len(context.get("top_findings",[]))}}


# ===========================================================================
# CLI REPORT FORMATTING — fully modular
# ===========================================================================

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_SEVERITY_ICON  = {"Critical": "🔴", "High": "🟠", "Medium": "🔵", "Low": "🟢"}
_SEVERITY_COLOR = {
    "Critical": C_RED + C_BRIGHT, "High": C_YELLOW + C_BRIGHT,
    "Medium":   C_BLUE + C_BRIGHT, "Low": C_GREEN + C_BRIGHT,
}

# Ordered (keywords, suggestion) — first match wins
_SINK_FIX_MAP: List[Tuple[List[str], str]] = [
    (["command injection","command execution","system"],
     "Sanitize all input before system(); prefer execv()/execve() to avoid shell interpretation."),
    (["format string"],
     "Use a literal format string: printf(\"%s\", var) — never printf(var)."),
    (["gets"],
     "Replace gets() with fgets(buf, sizeof(buf), stdin). gets() has no bounds check and is removed in C11."),
    (["strcpy"],
     "Replace strcpy(dst,src) with strncpy(dst,src,sizeof(dst)-1); dst[sizeof(dst)-1]='\\0';"),
    (["sprintf"],
     "Replace sprintf(dst,fmt,...) with snprintf(dst,sizeof(dst),fmt,...) to cap write length."),
    (["buffer overflow","unbounded copy","unbounded write","unbounded read"],
     "Add explicit bounds checks before every copy/write. Use: fgets, strncpy, snprintf, memcpy with size guard."),
    (["memory","malloc","free"],
     "Check malloc() return for NULL. Set pointer to NULL after free() to prevent use-after-free."),
    (["integer overflow","int overflow"],
     "Validate operands before arithmetic. Use a wider type or a checked integer library."),
]


def _severity_rank(sev: str) -> int:
    return _SEVERITY_ORDER.get(sev, 4)


def _normalise_severity(raw: Any) -> str:
    s = str(raw or "").strip().capitalize()
    return s if s in _SEVERITY_ORDER else "Low"


def _format_confidence(raw: Any) -> str:
    """0.5789 → 'Medium (0.58)'"""
    if raw is None: return "Unknown"
    try:    score = float(raw)
    except: return "Unknown"
    label = "High" if score > 0.70 else "Medium" if score > 0.50 else "Low"
    return f"{label} ({score:.2f})"


def _fix_suggestion(finding: Dict[str, Any]) -> str:
    vuln_type = str(finding.get("type", ""))
    explanation = str(finding.get("explanation", ""))
    corpus = f"{vuln_type} {explanation}".lower()

    if "gets(" in corpus or " gets " in f" {corpus} ":
        return "Use fgets() instead of gets()."
    if "strcpy(" in corpus or " strcpy " in f" {corpus} ":
        return "Use strncpy() with bounds checking."
    if "sprintf(" in corpus or " sprintf " in f" {corpus} ":
        return "Use snprintf() to prevent overflow."
    if "system(" in corpus or " system " in f" {corpus} ":
        return "Avoid system(); validate or sanitize input."

    return "Validate input and use safe, bounded APIs."


def _safe(v: Any, default: str = "Unknown") -> str:
    s = str(v or "").strip()
    return s if s else default


def _truncate(text: str, n: int = 280) -> str:
    s = " ".join(str(text).split())
    return s if len(s) <= n else s[:n-3] + "..."


def _normalise_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    explanation = raw.get("explanation")
    summary = (_truncate(str(explanation), 280)
               if explanation and str(explanation).strip()
               else "No explanation provided.")
    return {
        "severity":   _normalise_severity(raw.get("severity")),
        "title":      _safe(raw.get("type")),
        "file":       _safe(raw.get("file")),
        "line":       _safe(raw.get("line")),
        "function":   _safe(raw.get("function_name") or raw.get("function")),
        "cwe":        _safe(raw.get("cwe")),
        "cve":        _safe(raw.get("cve")),
        "cvss":       _safe(raw.get("cvss_score")),
        "confidence": _format_confidence(raw.get("confidence")),
        "summary":    summary,
        "fix":        _fix_suggestion(raw),
        "_pv":        raw.get("patch_verification"),
        "_ti":        raw.get("threat_intel_match"),
    }


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove exact duplicates by (file, line, function, cwe, type)."""
    seen: set = set()
    unique: List[Dict[str, Any]] = []
    for f in findings or []:
        key = (f.get("file"), f.get("line"),
               f.get("function_name") or f.get("function"),
               f.get("cwe"), f.get("type"))
        if key in seen: continue
        seen.add(key); unique.append(f)
    return unique


def compute_summary(normalised: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in normalised:
        sev = f.get("severity", "Low")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def format_finding(f: Dict[str, Any], index: int, show_patch: bool = False) -> str:
    sev   = f.get("severity", "Low")
    icon  = _SEVERITY_ICON.get(sev, "⚪")
    color = _SEVERITY_COLOR.get(sev, C_WHITE)
    lines = [
        f"  [{index}] {color}{icon} {sev}{C_RESET} - {f['title']}",
        "",
        f"    {C_WHITE}File:      {C_RESET}{f['file']}:{f['line']}",
        f"    {C_WHITE}Function:  {C_RESET}{f['function']}",
        "",
        f"    {C_WHITE}CWE:       {C_YELLOW}{C_BRIGHT}{f['cwe']}{C_RESET}",
        f"    {C_WHITE}CVE:       {C_RESET}{f['cve']}",
        f"    {C_WHITE}CVSS:      {C_RESET}{f['cvss']}",
        f"    {C_WHITE}Confidence:{C_RESET} {f['confidence']}",
    ]
    if f.get("_ti"):
        lines.append(f"    {C_MAGENTA}⚡ Matched threat intelligence database{C_RESET}")
    lines += [
        "",
        f"    {C_CYAN}{C_BRIGHT}Summary:{C_RESET}",
        f"    {f['summary']}",
        "",
        f"    {C_CYAN}{C_BRIGHT}Fix:{C_RESET}",
        f"    {C_GREEN}{f['fix']}{C_RESET}",
    ]
    pv = f.get("_pv")
    if isinstance(pv, dict) and pv:
        status = pv.get("status", "FAILED")
        badge  = (f"{C_GREEN}✓ VALIDATED{C_RESET}"   if status == "VALIDATED" else
                  f"{C_YELLOW}~ NO_EVIDENCE{C_RESET}" if status == "NO_EVIDENCE" else
                  f"{C_RED}✗ FAILED{C_RESET}")
        lines.append(
            f"    {C_WHITE}Patch:     {C_RESET}{badge} "
            f"(tainted sinks: {pv.get('original_tainted_sinks','-')} → {pv.get('patched_tainted_sinks','-')})"
        )
    lines += ["", "  " + "-" * 68]
    return "\n".join(lines)


def render_report(report: Dict[str, Any], show_patch: bool = False) -> str:
    """
    Full formatted report pipeline:
      deduplicate → normalise → sort by severity → compute_summary → string
    """
    deduped     = deduplicate_findings(report.get("vulnerabilities", []))
    normalised  = [_normalise_finding(f) for f in deduped]
    sorted_f    = sorted(normalised, key=lambda f: (_severity_rank(f.get("severity","Low")), f.get("file",""), f.get("line","")))
    summary     = compute_summary(sorted_f)

    lines: List[str] = []

    lines.append(f"\n{C_BRIGHT}{C_CYAN}{'=' * 72}{C_RESET}")
    lines.append(f"{C_BRIGHT}{C_CYAN}  SECURITY SCAN REPORT{C_RESET}")
    lines.append(f"{C_BRIGHT}{C_CYAN}{'=' * 72}{C_RESET}\n")

    for label, value in [
        ("Scan ID",  report.get("scan_id",    "-")),
        ("Created",  report.get("created_at", "-")),
        ("Query",    report.get("query",      "-")),
        ("Files",    ", ".join(report.get("files_scanned", [])) or "-"),
        ("Totals",   f"functions={report.get('summary',{}).get('total_functions',0)} | "
                     f"vulnerabilities={report.get('summary',{}).get('total_vulnerabilities',0)}"),
    ]:
        lines.append(f"  {C_WHITE}{label+':':10}{C_RESET} {value}")
    lines.append("")

    lines.append(
        f"  {C_RED}{C_BRIGHT}Critical: {summary['Critical']}{C_RESET}  "
        f"{C_YELLOW}{C_BRIGHT}High: {summary['High']}{C_RESET}  "
        f"{C_BLUE}{C_BRIGHT}Medium: {summary['Medium']}{C_RESET}  "
        f"{C_GREEN}{C_BRIGHT}Low: {summary['Low']}{C_RESET}"
    )
    lines.append("")

    if not sorted_f:
        lines.append(f"  {C_GREEN}✓ No vulnerabilities detected.{C_RESET}\n")
        return "\n".join(lines)

    lines.append(f"  {C_BRIGHT}{C_CYAN}FINDINGS{C_RESET}\n")
    for idx, finding in enumerate(sorted_f, 1):
        lines.append(format_finding(finding, idx, show_patch=show_patch))

    return "\n".join(lines)


def print_report(report: Dict[str, Any], show_patch: bool = False):
    print(render_report(report, show_patch=show_patch))


def _print_cli_report(report: Dict[str, Any]):
    print_report(report, show_patch=False)


# ===========================================================================
# FastAPI routes
# ===========================================================================

app = FastAPI(title="Code Forensics API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}

@app.post("/rag/refresh")
def refresh_rag() -> Dict[str, Any]:
    try:
        return {"status": "ok", "stats": _get_pipeline().rag_engine.refresh()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"RAG refresh failed: {exc}")

@app.post("/scan")
def scan_code(request: ScanRequest) -> Dict[str, Any]:
    try:
        safe = _validate_scan_folder(request.folder)
        report = _get_pipeline().run_scan(safe, request.query, request.generate_patches)
        report["cli_report"] = render_report(report, show_patch=False)
        _print_cli_report(report)
        return report
    except HTTPException: raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}")

@app.post("/scan/upload")
async def scan_upload(file: UploadFile = File(...), query: str = "scan all", generate_patches: bool = True) -> Dict[str, Any]:
    try:
        suffix = os.path.splitext(file.filename or "upload.c")[1] or ".c"
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, f"uploaded{suffix}")
            with open(path, "wb") as h: h.write(await file.read())
            return _get_pipeline().run_scan(tmp, query=query, generate_patches=generate_patches)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Upload scan failed: {exc}")

@app.get("/scan/{scan_id}")
def get_scan(scan_id: str) -> Dict[str, Any]:
    payload = _get_pipeline().repo.get_scan(scan_id)
    if payload is None: raise HTTPException(status_code=404, detail="Scan not found")
    return payload

@app.get("/scans")
def list_scans() -> List[Dict[str, Any]]:
    return _get_pipeline().repo.list_scans(limit=50)

@app.post("/feedback")
def add_feedback(request: FeedbackRequest) -> Dict[str, Any]:
    _get_pipeline().repo.add_feedback(
        scan_id=request.scan_id, vulnerability_id=request.vulnerability_id,
        is_false_positive=request.is_false_positive, comment=request.comment)
    return {"status": "saved"}

@app.post("/assistant/ask")
def ask_assistant(request: AssistantAskRequest) -> Dict[str, Any]:
    try:
        return _get_pipeline().ask_assistant(request.prompt, request.scan_id, request.top_findings)
    except ValueError as exc: raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:  raise HTTPException(status_code=500, detail=f"Assistant query failed: {exc}")


# ===========================================================================
# CLI
# ===========================================================================

def cli_main():
    p = _get_pipeline()
    print(f"\n{C_BRIGHT}{C_CYAN}=== CODE FORENSICS PLATFORM ==={C_RESET}")
    print(f"{C_DIM}Model: {MODEL_NAME} | RAG entries: {len(p.rag_engine.entries)}{C_RESET}")
    print(f"{C_DIM}Commands: scan [query] | scan --json | scan --patch | list scans | exit{C_RESET}\n")
    os.makedirs("code_samples", exist_ok=True)
    while True:
        try: query = input(f"{C_CYAN}forensics>> {C_RESET}").strip()
        except (EOFError, KeyboardInterrupt): print("\nExiting."); break
        nq = query.lower()
        if nq in {"exit", "quit"}: break
        if nq == "list scans": print(json.dumps(p.repo.list_scans(limit=20), indent=2)); continue
        show_json  = "--json"  in nq
        show_patch = "--patch" in nq
        clean_q    = query.replace("--json","").replace("--patch","").strip() or "scan all"
        report = p.run_scan(folder="code_samples", query=clean_q, generate_patches=True, verbose=True)
        if show_json: print(json.dumps(report, indent=2))
        else:         print_report(report, show_patch=show_patch)


if __name__ == "__main__":
    cli_main()