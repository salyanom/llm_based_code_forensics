import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.scanner.language_detector import LanguageDetector
from plugins import get_plugin_registry

def run_demo():
    print("--- Language Detector Demo ---")
    registry = get_plugin_registry()
    detector = LanguageDetector(registry)
    
    test_files = ["main.c", "app.py", "unknown_file.xyz"]
    
    for f in test_files:
        lang, plugin = detector.detect(f)
        print(f"File: {f} -> Language: {lang}, Supported: {plugin is not None}")

if __name__ == "__main__":
    run_demo()
