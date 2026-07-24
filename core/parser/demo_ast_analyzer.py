import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.parser.tree_sitter_parser import TreeSitterParser
from core.parser.ast_analyzer import ASTAnalyzer
from plugins import get_plugin_registry

def run_demo():
    print("--- AST Analyzer Demo ---")
    registry = get_plugin_registry()
    ts_parser = TreeSitterParser(registry)
    analyzer = ASTAnalyzer(ts_parser)
    
    code = "int main() { printf(\"Hello World\"); return 0; }"
    lang_id = "c"
    plugin = registry.get_plugin_by_id(lang_id)
    
    print(f"Parsing C code:\n{code}\n")
    
    result = analyzer.parse_and_extract(code, lang_id, plugin, "main.c")
    
    print(f"Functions found: {len(result['functions'])}")
    for f in result["functions"]:
        print(f"  - {f['function_name']} (lines {f['start_line']}-{f['end_line']})")
    
    print(f"Calls made: {result['calls']}")

if __name__ == "__main__":
    run_demo()
