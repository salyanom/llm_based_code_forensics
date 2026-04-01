from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from cvss import CVSS3
except Exception:
    CVSS3 = None

from services.llm_service import LLMService


class VerificationAgent:
    def __init__(self, llm_service: LLMService):
        self.llm_service = llm_service

    @staticmethod
    def _normalize_cvss_metrics(metrics: Dict[str, Any]) -> Dict[str, str]:
        raw = {k.lower(): str(v).strip().upper() for k, v in (metrics or {}).items() if v is not None}

        av_map = {
            "NETWORK": "N", "N": "N",
            "ADJACENT": "A", "A": "A", "ADJACENT_NETWORK": "A",
            "LOCAL": "L", "L": "L",
            "PHYSICAL": "P", "P": "P",
        }
        ac_map = {"LOW": "L", "L": "L", "HIGH": "H", "H": "H"}
        pr_map = {"NONE": "N", "N": "N", "LOW": "L", "L": "L", "HIGH": "H", "H": "H"}
        ui_map = {"NONE": "N", "N": "N", "REQUIRED": "R", "R": "R"}
        s_map = {"UNCHANGED": "U", "U": "U", "CHANGED": "C", "C": "C"}
        cia_map = {"NONE": "N", "N": "N", "LOW": "L", "L": "L", "HIGH": "H", "H": "H"}

        av = av_map.get(raw.get("attack_vector") or raw.get("av"), "L")
        ac = ac_map.get(raw.get("attack_complexity") or raw.get("ac"), "L")
        pr = pr_map.get(raw.get("privileges_required") or raw.get("pr"), "N")
        ui = ui_map.get(raw.get("user_interaction") or raw.get("ui"), "N")
        scope = s_map.get(raw.get("scope") or raw.get("s"), "U")
        conf = cia_map.get(raw.get("confidentiality_impact") or raw.get("c"), "L")
        integ = cia_map.get(raw.get("integrity_impact") or raw.get("i"), "L")
        avail = cia_map.get(raw.get("availability_impact") or raw.get("a"), "L")

        return {"AV": av, "AC": ac, "PR": pr, "UI": ui, "S": scope, "C": conf, "I": integ, "A": avail}

    @staticmethod
    def _fallback_score(metrics: Dict[str, str]) -> float:
        weights = {
            "AV": {"N": 1.2, "A": 0.95, "L": 0.7, "P": 0.3},
            "AC": {"L": 1.0, "H": 0.35},
            "PR": {"N": 1.1, "L": 0.6, "H": 0.25},
            "UI": {"N": 1.0, "R": 0.45},
            "C": {"N": 0.0, "L": 0.55, "H": 1.2},
            "I": {"N": 0.0, "L": 0.55, "H": 1.2},
            "A": {"N": 0.0, "L": 0.55, "H": 1.2},
        }
        base = 0.0
        for key in ["AV", "AC", "PR", "UI", "C", "I", "A"]:
            base += weights[key].get(metrics.get(key, "N"), 0.0)
        score = min(10.0, round((base / 7.5) * 10.0, 1))
        return score

    @staticmethod
    def _severity_from_score(score: float) -> str:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score > 0.0:
            return "Low"
        return "Info"

    def score_cvss(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        normalized = self._normalize_cvss_metrics(metrics)
        vector = f"CVSS:3.1/AV:{normalized['AV']}/AC:{normalized['AC']}/PR:{normalized['PR']}/UI:{normalized['UI']}/S:{normalized['S']}/C:{normalized['C']}/I:{normalized['I']}/A:{normalized['A']}"

        if CVSS3 is None:
            score = self._fallback_score(normalized)
            return {"vector": vector, "score": score, "severity": self._severity_from_score(score)}

        try:
            cvss_obj = CVSS3(vector)
            score = float(cvss_obj.scores()[0])
            severity = self._severity_from_score(score)
            return {"vector": vector, "score": score, "severity": severity}
        except Exception:
            score = self._fallback_score(normalized)
            return {"vector": vector, "score": score, "severity": self._severity_from_score(score)}

    @staticmethod
    def _floor_severity(result: Dict[str, Any]) -> str:
        current = result.get("severity", "Info")
        severity_rank = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

        vuln_type = str(result.get("type", "")).lower()
        cwe = str(result.get("cwe", "")).upper()
        floor = current

        if "command injection" in vuln_type or cwe == "CWE-78":
            floor = "High"
        elif "buffer overflow" in vuln_type or cwe in {"CWE-120", "CWE-121", "CWE-122"}:
            floor = "High"
        elif "format string" in vuln_type or cwe == "CWE-134":
            floor = "Medium"

        if severity_rank.get(floor, 0) > severity_rank.get(current, 0):
            return floor
        return current

    @staticmethod
    def _looks_like_command_injection(item: Dict[str, Any]) -> bool:
        text = (str(item.get("type", "")) + " " + str(item.get("explanation", ""))).lower()
        return "command injection" in text or "cwe-78" in text

    @staticmethod
    def _looks_like_buffer_issue(item: Dict[str, Any]) -> bool:
        text = (str(item.get("type", "")) + " " + str(item.get("explanation", ""))).lower()
        return any(token in text for token in ["buffer", "overflow", "strcpy", "sprintf", "gets", "cwe-120", "cwe-121", "cwe-122"])

    def _evidence_filter(self, finding: Dict[str, Any], item: Dict[str, Any]) -> bool:
        flows = finding.get("taint_flows", [])
        flow_types = {str(flow.get("type", "")) for flow in flows}

        if self._looks_like_command_injection(item):
            return "SINK" in flow_types or "SOURCE" in flow_types

        if self._looks_like_buffer_issue(item):
            return bool(flow_types.intersection({"UNBOUNDED_COPY", "UNBOUNDED_WRITE", "UNBOUNDED_READ", "BUFFER_OVERFLOW_RISK"}))

        return True

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        try:
            if value is None or value == "":
                return None
            return int(value)
        except Exception:
            return None

    @staticmethod
    def _canonical_family(vuln_type: str, cwe: str) -> str:
        text = (vuln_type or "").lower()
        cwe_norm = (cwe or "").upper().strip()

        if "command injection" in text or cwe_norm == "CWE-78":
            return "command_injection"
        if "format string" in text or cwe_norm == "CWE-134":
            return "format_string"
        if cwe_norm in {"CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787"}:
            return "buffer_memory"
        if any(token in text for token in ["buffer", "overflow", "unbounded", "gets", "strcpy", "sprintf"]):
            return "buffer_memory"
        return "other"

    def _is_evidence_consistent(self, finding: Dict[str, Any], vuln_type: str, cwe: str, line: Optional[int]) -> bool:
        flows = finding.get("taint_flows", [])
        family = self._canonical_family(vuln_type, cwe)

        def lines_for(flow_types: Set[str], sink_functions: Optional[Set[str]] = None) -> Set[int]:
            candidates: Set[int] = set()
            for flow in flows:
                if str(flow.get("type", "")) not in flow_types:
                    continue
                if sink_functions and str(flow.get("function", "")) not in sink_functions:
                    continue
                fl = self._safe_int(flow.get("line"))
                if fl is not None:
                    candidates.add(fl)
            return candidates

        if family == "command_injection":
            ci_lines = lines_for({"SINK"}, {"system", "exec", "execl", "popen"})
            if not ci_lines:
                return False
            return line is None or line in ci_lines

        if family == "format_string":
            fs_lines = lines_for({"FORMAT_STRING_RISK"})
            if not fs_lines:
                return False
            return line is None or line in fs_lines

        if family == "buffer_memory":
            mem_lines = lines_for({"UNBOUNDED_COPY", "UNBOUNDED_WRITE", "UNBOUNDED_READ", "BUFFER_OVERFLOW_RISK"})
            if not mem_lines:
                return False
            return line is None or line in mem_lines

        return True

    def _rule_based_findings(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        flows = finding.get("taint_flows", [])
        out: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, Optional[int]]] = set()

        defaults = {
            "command_injection": {
                "vulnerability": "Command Injection",
                "cwe": "CWE-78",
                "explanation": "User-controlled input reaches a command execution sink.",
                "cvss_metrics": {
                    "attack_vector": "NETWORK",
                    "attack_complexity": "LOW",
                    "privileges_required": "NONE",
                    "user_interaction": "NONE",
                    "scope": "UNCHANGED",
                    "confidentiality_impact": "HIGH",
                    "integrity_impact": "HIGH",
                    "availability_impact": "HIGH",
                },
            },
            "buffer_memory": {
                "vulnerability": "Buffer Overflow",
                "cwe": "CWE-120",
                "explanation": "Unbounded copy/read/write operation can exceed destination bounds.",
                "cvss_metrics": {
                    "attack_vector": "LOCAL",
                    "attack_complexity": "LOW",
                    "privileges_required": "NONE",
                    "user_interaction": "NONE",
                    "scope": "UNCHANGED",
                    "confidentiality_impact": "LOW",
                    "integrity_impact": "HIGH",
                    "availability_impact": "HIGH",
                },
            },
            "format_string": {
                "vulnerability": "Format String Vulnerability",
                "cwe": "CWE-134",
                "explanation": "Non-literal format string may allow memory disclosure or control.",
                "cvss_metrics": {
                    "attack_vector": "LOCAL",
                    "attack_complexity": "LOW",
                    "privileges_required": "NONE",
                    "user_interaction": "NONE",
                    "scope": "UNCHANGED",
                    "confidentiality_impact": "LOW",
                    "integrity_impact": "LOW",
                    "availability_impact": "LOW",
                },
            },
        }

        for flow in flows:
            flow_type = str(flow.get("type", ""))
            flow_fn = str(flow.get("function", ""))
            flow_line = self._safe_int(flow.get("line"))

            family = None
            if flow_type == "SINK" and flow_fn in {"system", "exec", "execl", "popen"}:
                family = "command_injection"
            elif flow_type in {"UNBOUNDED_COPY", "UNBOUNDED_WRITE", "UNBOUNDED_READ", "BUFFER_OVERFLOW_RISK"}:
                family = "buffer_memory"
            elif flow_type == "FORMAT_STRING_RISK":
                family = "format_string"

            if not family:
                continue

            key = (family, flow_line)
            if key in seen:
                continue
            seen.add(key)

            template = defaults[family]
            explanation = f"{template['explanation']} Evidence: {flow_fn} at line {flow_line}."
            out.append(
                {
                    "vulnerability": template["vulnerability"],
                    "line": flow_line,
                    "cwe": template["cwe"],
                    "cve": "Unknown",
                    "threat_intel_match": family in {"command_injection", "buffer_memory"},
                    "explanation": explanation,
                    "cvss_metrics": template["cvss_metrics"],
                    "_source": "rule",
                }
            )

        return out

    @staticmethod
    def _line_from_explanation(item: Dict[str, Any]) -> Any:
        if item.get("line"):
            return item.get("line")
        exp = str(item.get("explanation", ""))
        match = re.search(r"line\s*(\d+)", exp, flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None

    def verify(self, finding: Dict[str, Any], rag_matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        report_items = self.llm_service.analyze_vulnerabilities(finding, rag_matches)
        report_items.extend(self._rule_based_findings(finding))
        enriched: List[Dict[str, Any]] = []
        seen = set()
        max_rag_conf = max([float(item.get("confidence", 0.0)) for item in rag_matches], default=0.0)

        for item in report_items:
            if not self._evidence_filter(finding, item):
                continue

            raw_type = item.get("vulnerability") or item.get("type") or "Unknown"
            raw_cwe = item.get("cwe", "Unknown")
            raw_line = self._safe_int(item.get("line")) or self._line_from_explanation(item)
            if not self._is_evidence_consistent(finding, str(raw_type), str(raw_cwe), self._safe_int(raw_line)):
                continue

            cvss_data = self.score_cvss(item.get("cvss_metrics", {}))
            result = {
                "type": raw_type,
                "severity": cvss_data["severity"],
                "line": raw_line,
                "cwe": raw_cwe,
                "cve": item.get("cve", "Unknown"),
                "cvss_score": cvss_data["score"],
                "cvss_vector": cvss_data["vector"],
                "threat_intel_match": bool(item.get("threat_intel_match", False)),
                "explanation": item.get("explanation", ""),
                "confidence": round(max_rag_conf, 4),
            }

            result["severity"] = self._floor_severity(result)

            family = self._canonical_family(str(result.get("type", "")), str(result.get("cwe", "Unknown")))
            dedupe_key = (family, result.get("line"))
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            enriched.append(result)

        return enriched
