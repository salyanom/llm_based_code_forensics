import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.forensics.agents.categorization_agent import CategorizationAgent
from core.forensics.agents.validation_agent import ValidationAgent
from core.forensics.agents.explainability_agent import ExplainabilityAgent
from core.forensics.agents.advisory_refactoring_agent import AdvisoryRefactoringAgent

def demo():
    print("--- Phase 3D: Agentic Forensics Pipeline Demo ---")
    
    cat_agent = CategorizationAgent()
    val_agent = ValidationAgent()
    exp_agent = ExplainabilityAgent()
    patch_agent = AdvisoryRefactoringAgent()
    
    correlated_item = {
        "file_path": "test.c",
        "language": "c",
        "function_name": "test",
        "start_line": 10,
        "end_line": 15,
        "sink": "strcpy",
        "line_text": "strcpy(buf, input);",
        "rag_context": {
            "cwe": "CWE-120",
            "cve": "Unknown",
            "owasp_recommendation": "Use bounded copies.",
        }
    }
    
    llm_response = {
        "is_vulnerable": True,
        "vulnerability_type": "CWE-120",
        "confidence": 95,
        "explanation": "The buffer is not checked before copying.",
        "suggested_patch": "strncpy(buf, input, sizeof(buf) - 1);\n    buf[sizeof(buf) - 1] = '\\0';"
    }
    
    print("\n1. Categorization Agent")
    categorization = cat_agent.categorize(correlated_item, llm_response)
    print(f"CWE: {categorization['cwe']} | Severity: {categorization['severity']} | CVSS: {categorization['cvss_score']}")
    
    print("\n2. Validation Agent")
    verified_finding = val_agent.validate(correlated_item, categorization, llm_response)
    print(f"Final Confidence: {verified_finding['confidence']}%")
    
    print("\n3. Explainability Agent")
    explanation = exp_agent.generate_evidence_explanation(verified_finding)
    print(explanation["why"][:100] + "...")
    
    print("\n4. Advisory Refactoring Agent")
    patch_result = patch_agent.generate_patch_for_finding(verified_finding, "void test(char *input) {\n    char buf[10];\n    strcpy(buf, input);\n}")
    print(f"Patch Valid: {patch_result['is_valid']}")
    print("Unified Diff generated successfully.")

if __name__ == "__main__":
    demo()
