import os
import time
from typing import Any, Callable, Dict, List, Optional

from config_manager import ConfigManager
from modules.parser import ASTParserModule
from modules.correlation import CorrelationModule
from modules.llm_engine import LLMEngine
from modules.verification import VerificationModule
from modules.patch_generation import PatchGenerationModule
from modules.explainability import ExplainabilityModule
from modules.persistence import PersistenceModule
from modules.prompt_builder import PromptBuilderModule

class SecurityPipeline:
    """
    Phase 0: Central Orchestrator
    Coordinates the execution of scanning, RAG correlation, and LLM verification.
    Currently acts as a wrapper around existing `modules/*`.
    """

    def __init__(self):
        self.config_mgr = ConfigManager.get_instance()
        self.persistence = PersistenceModule()
        self.parser_module = ASTParserModule()
        self.correlation_module = CorrelationModule()
        self.llm_engine = LLMEngine()
        self.verification_module = VerificationModule()
        self.patch_module = PatchGenerationModule()
        self.explainability_module = ExplainabilityModule()
        self.prompt_builder = PromptBuilderModule()

    def run_scan(
        self, 
        project_folder: str, 
        project_id: int, 
        force_reparse: bool,
        stage_callback: Callable[[str, str, str], None],
        log_callback: Callable[[str, str], None]
    ) -> Dict[str, Any]:
        """
        Executes the full pipeline sequentially and returns the final report payload.
        """
        start_t = time.time()
        log_callback(f"Scan started (incremental={not force_reparse})", "STAGE")

        # ── Parse ──
        stage_callback("parse", "running", "")
        parser_res = self.parser_module.scan_project(project_folder, force_reparse=force_reparse)
        file_results = parser_res.get("file_results", {})
        scanned = parser_res.get("files_scanned", 0)
        cached = parser_res.get("files_from_cache", 0)
        stage_callback("parse", "done", f"{scanned} files ({cached} cached)")
        log_callback(f"Parser: {scanned} files scanned, {cached} from cache", "INFO")

        scan_id = self.persistence.create_scan_run(project_id, scanned, 0)

        all_findings: List[Dict[str, Any]] = []
        badge_counts: Dict[str, int] = {}

        # ── Correlate ──
        stage_callback("correlate", "running", "")
        for fpath, analysis in file_results.items():
            lang = analysis.get("language", "unknown")
            correlated = self.correlation_module.correlate_file_findings(fpath, lang, analysis)
            analysis["_correlated"] = correlated
        total_corr = sum(len(a.get("_correlated", [])) for a in file_results.values())
        stage_callback("correlate", "done", f"{total_corr} candidates")
        log_callback(f"Correlation: {total_corr} candidates found", "INFO")

        # ── LLM Connect ──
        self.config_mgr.reload()
        conn_status = self.llm_engine.check_connection()
        llm_online = conn_status.get("status") == "ONLINE"
        if llm_online:
            stage_callback("llm", "running", "")
            latency = conn_status.get("latency_ms", 0)
            model_name = conn_status.get("model", "?")
            log_callback(f"LLM online ({model_name}, {latency}ms) — running verification", "INFO")
        else:
            stage_callback("llm", "skip", "offline")
            err_info = conn_status.get("error") or conn_status.get("exception", "Unknown error")
            log_callback(f"LLM offline ({err_info}) — skipping inference", "WARNING")

        # ── Verify + Patch + Explain ──
        stage_callback("verify", "running", "")
        stage_callback("patch", "running", "")
        stage_callback("explain", "running", "")

        for fpath, analysis in file_results.items():
            lang = analysis.get("language", "unknown")
            file_count = 0
            for corr in analysis.get("_correlated", []):
                llm_resp: Dict[str, Any] = {}
                if llm_online:
                    try:
                        prompt = self.prompt_builder.build_verification_prompt(
                            corr, corr.get("rag_context", {}), lang)
                        llm_resp = self.llm_engine.execute_inference(prompt)
                    except Exception as exc:
                        log_callback(f"Inference exception: {exc}", "ERROR")

                verified = self.verification_module.verify_finding(corr, llm_resp)
                if verified.get("severity") != "Info" and verified.get("confidence", 0) >= 40:
                    patch_info = self.patch_module.generate_patch_for_finding(verified)
                    verified["patch_diff"] = patch_info.get("unified_diff", "")
                    verified["patched_snippet"] = patch_info.get("patched_snippet", "")
                    verified["explanation_json"] = (
                        self.explainability_module.generate_evidence_explanation(verified))
                    all_findings.append(verified)
                    file_count += 1

            if file_count > 0:
                badge_counts[fpath] = file_count

        if llm_online:
            stage_callback("llm", "done", "")
        stage_callback("verify",  "done", f"{len(all_findings)} findings verified")
        stage_callback("patch",   "done", "")
        stage_callback("explain", "done", "")

        # ── Persist ──
        stage_callback("persist", "running", "")
        self.persistence.save_vulnerabilities(scan_id, all_findings)
        self.persistence.update_scan_findings_count(scan_id, len(all_findings))
        stage_callback("persist", "done", f"{len(all_findings)} records written")
        log_callback(f"Persistence: {len(all_findings)} records saved", "INFO")

        vulnerabilities_list = sorted(
            all_findings,
            key=lambda x: (x.get("cvss_score", 0), x.get("confidence", 0)),
            reverse=True)

        elapsed = round(time.time() - start_t, 3)
        msg = (f"Scan done in {elapsed}s  |  "
               f"{scanned} files  ({cached} cached)  |  "
               f"{len(vulnerabilities_list)} findings")
        log_callback(msg, "INFO")
        self.persistence.log_scan_message(scan_id, msg)

        return {
            "scan_id": scan_id,
            "message": msg,
            "vulnerabilities": vulnerabilities_list,
            "badge_counts": badge_counts,
            "scanned": scanned,
            "cached": cached
        }
