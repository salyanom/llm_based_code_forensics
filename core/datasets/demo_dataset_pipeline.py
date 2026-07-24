import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.datasets.preprocessing import DatasetPreprocessor

def run_demo():
    print("--- Phase 2B: Offline Dataset Pipeline Demo ---")
    
    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    knowledge_dir = os.path.join(root_dir, "knowledge")
    data_dir = os.path.join(root_dir, "data")
    
    preprocessor = DatasetPreprocessor(root_dir, knowledge_dir, data_dir)
    print("Loading and normalizing offline datasets (Juliet, DiverseVul, PrimeVul, etc.)...")
    
    result = preprocessor.run_preprocessing_pipeline()
    
    print(f"Total raw dataset entries parsed: {result['total_raw']}")
    print(f"Unique canonical JSONL training entries exported: {result['unique_records']}")
    print(f"Export location: {result['output_path']}")

if __name__ == "__main__":
    run_demo()
