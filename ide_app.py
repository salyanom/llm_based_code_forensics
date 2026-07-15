#!/usr/bin/env python3
"""
AI-Powered Secure Code Forensics IDE
====================================
Modular desktop application combining multi-language Tree-sitter AST parsing,
LoRA-adapted DeepSeek-Coder vulnerability analysis, and vector-based RAG
threat intelligence.

Usage:
    python ide_app.py
"""
import sys
import os

# Ensure project root is in Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.ui_desktop import SecureCodeForensicsIDE


def main():
    print("[Secure Code Forensics IDE] Initializing modular architecture...")
    app = SecureCodeForensicsIDE()
    print("[Secure Code Forensics IDE] Application launched successfully.")
    app.mainloop()


if __name__ == "__main__":
    main()
