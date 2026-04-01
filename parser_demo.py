from tree_sitter import Parser
from tree_sitter_languages import get_language
from sentence_transformers import SentenceTransformer

C_LANGUAGE = get_language("c")

parser = Parser()
parser.set_language(C_LANGUAGE)

# Load embedding model
model = SentenceTransformer("all-MiniLM-L6-v2")

# Sample C code
code = b"""
#include <stdio.h>

int add(int a, int b){
    return a + b;
}

int multiply(int a, int b){
    return a * b;
}

int main(){
    int x = add(5,10);
    int y = multiply(2,3);
    printf("%d %d", x, y);
}
"""

# Parse code
tree = parser.parse(code)
root = tree.root_node


# ---------- Print Syntax Tree ----------
def print_tree(node, indent=0):
    print(" " * indent + node.type)
    for child in node.children:
        print_tree(child, indent + 2)


print("===== Syntax Tree =====")
print_tree(root)


# ---------- Extract Functions ----------
functions = []


def extract_functions(node):
    if node.type == "function_definition":
        func_text = code[node.start_byte:node.end_byte].decode()
        functions.append(func_text)

    for child in node.children:
        extract_functions(child)


extract_functions(root)

print("\n===== Extracted Functions =====")
for func in functions:
    print("\n", func)


# ---------- Generate Embeddings ----------
print("\n===== Vector Embeddings =====")
embeddings = model.encode(functions)

for i, func in enumerate(functions):
    print("\nFunction:\n", func)
    print("Vector Length:", len(embeddings[i]))