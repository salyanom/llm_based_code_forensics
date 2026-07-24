import unittest

from plugins import get_plugin_registry
from core.scanner.language_detector import LanguageDetector

class TestLanguageDetector(unittest.TestCase):
    def setUp(self):
        self.registry = get_plugin_registry()
        self.detector = LanguageDetector(self.registry)

    def test_detect_c_file(self):
        lang_id, plugin = self.detector.detect("test.c")
        self.assertEqual(lang_id, "c")
        self.assertIsNotNone(plugin)

    def test_detect_unknown_file(self):
        lang_id, plugin = self.detector.detect("test.unknown_extension")
        self.assertEqual(lang_id, "unknown")
        self.assertIsNone(plugin)

if __name__ == "__main__":
    unittest.main()
