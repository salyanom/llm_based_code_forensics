import os
import sys

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.scanner.repository_scanner import RepositoryScanner
from config_manager import ConfigManager

def run_demo():
    print("--- Repository Scanner Demo ---")
    config = ConfigManager.get_instance()
    scanner = RepositoryScanner(config)
    
    target_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests")
    print(f"Scanning target directory: {target_dir}")
    
    valid_files = scanner.get_files_to_scan(target_dir)
    print(f"Found {len(valid_files)} supported files to scan:")
    for f in valid_files:
        print(f"  - {os.path.basename(f)}")

if __name__ == "__main__":
    run_demo()
