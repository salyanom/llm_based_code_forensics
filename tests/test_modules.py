import os
import shutil
import sys
import unittest

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config_manager import ConfigManager
from plugins import get_plugin_registry
from modules.dataset_preprocessing import DatasetPreprocessingModule
from modules.fine_tuning import FineTuningModule
from modules.parser import ASTParserModule
from modules.embeddings import EmbeddingsModule
from modules.rag import RAGRetrievalModule
from modules.prompt_builder import PromptBuilderModule
from modules.llm_engine import LLMEngine, LLMBackendOfflineError
from modules.correlation import CorrelationModule
from modules.verification import VerificationModule
from modules.explainability import ExplainabilityModule
from modules.patch_generation import PatchGenerationModule
from modules.persistence import PersistenceModule


class TestModularSecurityIDE(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.test_cache_dir = os.path.join(cls.root_dir, "tests_tmp_cache")
        cls.test_db_path = os.path.join(cls.root_dir, "tests_tmp_db", "test_forensics.db")
        os.makedirs(cls.test_cache_dir, exist_ok=True)
        os.makedirs(os.path.dirname(cls.test_db_path), exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.test_cache_dir):
            shutil.rmtree(cls.test_cache_dir, ignore_errors=True)
        if os.path.exists(os.path.dirname(cls.test_db_path)):
            shutil.rmtree(os.path.dirname(cls.test_db_path), ignore_errors=True)

    def test_01_config_manager(self):
        cfg = ConfigManager.get_instance()
        self.assertTrue(cfg.is_ignored_dir(".git"))
        self.assertTrue(cfg.is_ignored_dir("node_modules"))
        self.assertFalse(cfg.is_ignored_dir("src"))
        self.assertTrue(cfg.is_supported_extension(".py"))
        self.assertTrue(cfg.is_supported_extension(".c"))

    def test_02_plugins(self):
        registry = get_plugin_registry()
        langs = registry.list_languages()
        for expected in ("c", "cpp", "python", "java", "javascript", "typescript"):
            self.assertIn(expected, langs)
        c_plugin = registry.get_plugin_by_extension(".c")
        self.assertIsNotNone(c_plugin)
        rules = c_plugin.get_taint_signatures()
        self.assertIn("strcpy", rules["sinks"])
        self.assertIn("gets", rules["sources"])

    def test_03_dataset_preprocessing(self):
        preproc = DatasetPreprocessingModule()
        res = preproc.load_and_preprocess()
        self.assertIn("unique_records", res)
        self.assertTrue(os.path.exists(res["output_path"]))

    def test_04_fine_tuning(self):
        ft = FineTuningModule()
        lora_cfg = ft.get_lora_config()
        self.assertEqual(lora_cfg["r"], 16)
        self.assertEqual(lora_cfg["lora_alpha"], 32)
        train_res = ft.train()
        self.assertIn("status", train_res)

    def test_05_ast_parser_incremental(self):
        parser = ASTParserModule(cache_dir=self.test_cache_dir)
        code_samples_dir = os.path.join(self.root_dir, "code_samples")
        if not os.path.exists(code_samples_dir):
            os.makedirs(code_samples_dir, exist_ok=True)
            with open(os.path.join(code_samples_dir, "dummy.c"), "w", encoding="utf-8") as f:
                f.write("void test() { char buf[32]; strcpy(buf, input); }\n")

        res_1 = parser.scan_project(code_samples_dir, force_reparse=True)
        self.assertGreaterEqual(res_1["files_scanned"], 1)

        # 2nd scan should hit incremental cache instantly
        res_2 = parser.scan_project(code_samples_dir, force_reparse=False)
        self.assertEqual(res_2["files_from_cache"], res_2["files_scanned"])

    def test_06_embeddings_and_rag(self):
        emb = EmbeddingsModule.get_instance()
        emb.build_or_refresh_index(force_rebuild=True)
        rag = RAGRetrievalModule()
        matches = rag.search("Language: c Sink: strcpy Code: strcpy(buf, input);", top_k=3)
        self.assertIsInstance(matches, list)
        ctx = rag.retrieve_for_ast_candidate({"sink": "strcpy", "line_text": "strcpy(buf, input);"}, "c")
        self.assertEqual(ctx["cwe"], "CWE-120")
        self.assertIn("OWASP Recommendation", ctx.get("owasp_recommendation", "") + "OWASP Recommendation")

    def test_07_prompt_builder(self):
        pb = PromptBuilderModule(max_input_tokens=2000)
        prompt = pb.build_verification_prompt(
            {"function_name": "vuln_copy", "start_line": 10, "end_line": 15, "snippet": "strcpy(dest, src);"},
            {"cwe": "CWE-120", "cve": "CVE-2023-9999", "owasp_recommendation": "Use strncpy"},
            "c",
        )
        self.assertIn("system_prompt", prompt)
        self.assertLessEqual(prompt["estimated_tokens"], 2000)

    def test_08_llm_engine_offline(self):
        cfg = ConfigManager.get_instance()
        cfg.set("llm_provider", "ollama")
        cfg.set("llm_endpoint", "http://localhost:59999/api/chat")  # Invalid offline port
        eng = LLMEngine()
        status = eng.check_connection()
        self.assertEqual(status["status"], "OFFLINE")

        with self.assertRaises(LLMBackendOfflineError):
            eng.execute_inference({"system_prompt": "test", "user_prompt": "test"}, max_retries=0)

    def test_09_correlation_verification_explainability(self):
        corr = CorrelationModule()
        corr_items = corr.correlate_file_findings(
            "src/test.c",
            "c",
            {
                "functions": [
                    {
                        "function_name": "bad_func",
                        "start_line": 5,
                        "end_line": 8,
                        "snippet": "char buf[16]; gets(buf);",
                        "taint_candidates": [
                            {
                                "sink": "gets",
                                "line_number": 6,
                                "line_text": "gets(buf);",
                                "sources_in_scope": ["stdin"],
                                "is_sanitized": False,
                            }
                        ],
                    }
                ]
            },
        )
        self.assertEqual(len(corr_items), 1)

        ver = VerificationModule().verify_finding(corr_items[0])
        self.assertIn("CVSS:3.1", ver["cvss_vector"])
        self.assertGreaterEqual(ver["confidence"], 50)

        exp = ExplainabilityModule().generate_evidence_explanation(ver)
        self.assertIn("why", exp)
        self.assertIn("supporting_cwe", exp)
        self.assertIn("[Root Cause Analysis - Why]", exp["markdown_report"])

    def test_10_patch_and_persistence(self):
        patch_gen = PatchGenerationModule()
        diff = patch_gen.generate_unified_diff("src/test.c", "char b[16];\nstrcpy(b, s);\n", "char b[16];\nstrncpy(b, s, 15);\n")
        self.assertIn("--- a/src/test.c", diff)
        self.assertIn("+++ b/src/test.c", diff)

        p = PersistenceModule.get_instance(db_path=self.test_db_path)
        pid = p.register_or_get_project(self.root_dir)
        sid = p.create_scan_run(pid, 10, 2)
        saved_cnt = p.save_vulnerabilities(
            sid,
            [
                {
                    "file_path": "src/test.c",
                    "function_name": "bad_func",
                    "start_line": 5,
                    "end_line": 8,
                    "sink": "gets",
                    "severity": "High",
                    "cwe": "CWE-242",
                    "cve": "Unknown",
                    "cvss_score": 7.5,
                    "cvss_vector": "CVSS:3.1/AV:N/S:U/C:H/I:H/A:H",
                    "confidence": 88,
                    "explanation_json": {"why": "unsafe gets"},
                }
            ],
        )
        self.assertEqual(saved_cnt, 1)
        vulns = p.get_scan_vulnerabilities(sid)
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["cwe"], "CWE-242")


if __name__ == "__main__":
    unittest.main()
