import unittest

from plugins import get_plugin_registry
from core.parser.tree_sitter_parser import TreeSitterParser
from core.parser.ast_analyzer import ASTAnalyzer

class TestASTAnalyzer(unittest.TestCase):
    def setUp(self):
        self.registry = get_plugin_registry()
        self.ts_parser = TreeSitterParser(self.registry)
        self.analyzer = ASTAnalyzer(self.ts_parser)

    def test_parse_and_extract(self):
        content = "int main() { printf(\"hello\"); return 0; }"
        lang_id = "c"
        plugin = self.registry.get_plugin_by_id(lang_id)
        
        result = self.analyzer.parse_and_extract(content, lang_id, plugin, "main.c")
        
        self.assertEqual(result["file_path"], "main.c")
        self.assertEqual(result["language"], "c")
        self.assertTrue(len(result["functions"]) > 0)
        self.assertEqual(result["functions"][0]["function_name"], "main")
        
        # In fallback mode (when tree-sitter C-binding is not compiled locally), 
        # calls and imports are not extracted by heuristic_parse.
        # We only assert calls if the full parser was available and found them.
        if self.ts_parser.parse(content.encode("utf-8"), lang_id):
            self.assertIn("printf", result["calls"])

if __name__ == "__main__":
    unittest.main()
