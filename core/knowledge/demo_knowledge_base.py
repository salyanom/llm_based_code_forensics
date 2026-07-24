import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.knowledge.threat.preprocessor import ThreatPreprocessor
from core.knowledge.embeddings.embedding_generator import EmbeddingGenerator
from core.knowledge.vector_store.vector_db import VectorDB

def run_demo():
    print("--- Phase 2A: Threat Knowledge Base Demo ---")
    
    knowledge_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "knowledge")
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
    
    preprocessor = ThreatPreprocessor(knowledge_dir)
    print("Loading and deduplicating threat records (NVD, OWASP)...")
    records = preprocessor.load_and_preprocess()
    print(f"Total unique threat records loaded: {len(records)}")
    
    if not records:
        print("No records found (ensure nvd.json and owasp.json exist in /knowledge).")
        return
        
    print(f"Sample threat: [{records[0]['cwe']}] {records[0]['title']}")
    
    generator = EmbeddingGenerator()
    print("Encoding texts to vector embeddings (this uses sentence-transformers or hash fallback)...")
    texts = [r['description'] for r in records[:5]] # Just encode 5 for demo
    vectors = generator.encode(texts)
    
    print(f"Vectors shape generated: {vectors.shape}")
    
    db = VectorDB(data_dir)
    print("Simulating VectorDB storage...")
    db.update_index(vectors, records[:5])
    
    print(f"Index successfully updated in {data_dir}. Index size: {db.get_index_size()}")
    
if __name__ == "__main__":
    run_demo()
