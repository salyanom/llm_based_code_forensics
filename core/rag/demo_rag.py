import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.rag.engine import RAGEngine

def demo():
    print("--- Phase 3C: Stateless RAG Engine Demo ---")
    engine = RAGEngine()
    
    query = "Language: c Sink: strcpy Code: strcpy(buf, input);"
    print(f"Querying vector database for: {query}")
    matches = engine.search(query, top_k=2)
    
    for i, m in enumerate(matches):
        print(f"\nMatch {i+1} [Score {m.get('similarity_score', 0)}]")
        print(f"CWE: {m.get('cwe')} | Source: {m.get('source')}")
        print(f"Text: {m.get('text')}")

    print("\nRetrieving structured RAG Context for AST candidate...")
    candidate = {"sink": "strcpy", "line_text": "strcpy(buf, input);"}
    context = engine.retrieve(candidate, "c")
    
    print(f"Associated CWE: {context.get('cwe')}")
    print(f"OWASP Recommendation: {context.get('owasp_recommendation')[:100]}...")

if __name__ == "__main__":
    demo()
