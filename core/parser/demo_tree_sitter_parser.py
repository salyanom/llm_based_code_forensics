import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.parser.tree_sitter_parser import TreeSitterParser
from plugins import get_plugin_registry

def run_demo():
    print("--- Tree-sitter Parser Demo ---")
    registry = get_plugin_registry()
    ts_parser = TreeSitterParser(registry)
    
    code = b"int main() { printf(\"Hello World\"); return 0; }"
    print(f"Parsing C code: {code}")
    
    tree = ts_parser.parse(code, "c")
    if tree:
        print(f"Successfully parsed! Root node type: {tree.root_node.type}")
    else:
        print("Failed to parse code.")

if __name__ == "__main__":
    run_demo()
