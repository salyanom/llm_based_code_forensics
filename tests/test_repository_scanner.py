import os
import tempfile
import unittest

from core.scanner.repository_scanner import RepositoryScanner
from config_manager import ConfigManager

class TestRepositoryScanner(unittest.TestCase):
    def setUp(self):
        self.config = ConfigManager.get_instance()
        self.scanner = RepositoryScanner(self.config)
        self.test_dir = tempfile.TemporaryDirectory()
        
        # Create some test files
        self.valid_c_file = os.path.join(self.test_dir.name, "test.c")
        with open(self.valid_c_file, "w") as f:
            f.write("int main() {}")
            
        self.ignored_dir = os.path.join(self.test_dir.name, ".git")
        os.makedirs(self.ignored_dir)
        self.ignored_file = os.path.join(self.ignored_dir, "config")
        with open(self.ignored_file, "w") as f:
            f.write("ignore me")
            
        self.unsupported_file = os.path.join(self.test_dir.name, "test.txt")
        with open(self.unsupported_file, "w") as f:
            f.write("text")

    def tearDown(self):
        self.test_dir.cleanup()

    def test_get_files_to_scan(self):
        files = self.scanner.get_files_to_scan(self.test_dir.name)
        
        self.assertIn(self.valid_c_file, files)
        self.assertNotIn(self.ignored_file, files)
        self.assertNotIn(self.unsupported_file, files)

if __name__ == "__main__":
    unittest.main()
