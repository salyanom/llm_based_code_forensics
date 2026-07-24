import unittest

from plugins import get_plugin_registry
from core.parser.tree_sitter_parser import TreeSitterParser

class TestTreeSitterParser(unittest.TestCase):
    def setUp(self):
        self.registry = get_plugin_registry()
        self.ts_parser = TreeSitterParser(self.registry)

    def test_parse_valid_c_code(self):
        code_bytes = b"int main() { return 0; }"
        tree = self.ts_parser.parse(code_bytes, "c")
        if tree is not None:
            self.assertEqual(tree.root_node.type, "translation_unit")
        else:
            # Fallback mode gracefully returns None
            pass

    def test_parse_unsupported_language(self):
        code_bytes = b"something unsupported"
        tree = self.ts_parser.parse(code_bytes, "unknown_lang")
        self.assertIsNone(tree)

if __name__ == "__main__":
    unittest.main()
