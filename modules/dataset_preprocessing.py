from __future__ import annotations
import os
from typing import Any, Dict, List

from core.datasets.preprocessing import DatasetPreprocessor

class DatasetPreprocessingModule:
    """
    Compatibility layer for offline Dataset Preprocessing.
    Delegates to Phase 2B core.datasets.preprocessing components.
    """

    def __init__(self, root_dir: str = None):
        self.root_dir = root_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.data_dir = os.path.join(self.root_dir, "data")
        self.knowledge_dir = os.path.join(self.root_dir, "knowledge")
        os.makedirs(self.data_dir, exist_ok=True)
        
        self.preprocessor = DatasetPreprocessor(self.root_dir, self.knowledge_dir, self.data_dir)

    def load_and_preprocess(self) -> Dict[str, Any]:
        """Alias for run_preprocessing_pipeline."""
        return self.run_preprocessing_pipeline()

    def run_preprocessing_pipeline(self) -> Dict[str, Any]:
        """Execute full normalization, deduplication, and export of training JSONL."""
        return self.preprocessor.run_preprocessing_pipeline()
