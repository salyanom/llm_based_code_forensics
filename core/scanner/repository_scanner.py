import os
from typing import List

class RepositoryScanner:
    """
    Extracted from modules/parser.py.
    Responsible for walking the repository and filtering files according to config rules.
    """
    def __init__(self, config):
        self.config = config

    def get_files_to_scan(self, folder_path: str) -> List[str]:
        valid_files = []
        for root, dirs, files in os.walk(folder_path):
            # Filter out ignored directories in place
            dirs[:] = [d for d in dirs if not self.config.is_ignored_dir(d)]

            for file_name in files:
                ext = os.path.splitext(file_name)[1].lower()
                if not self.config.is_supported_extension(ext):
                    continue

                file_path = os.path.join(root, file_name)
                try:
                    file_size = os.path.getsize(file_path)
                    if file_size > self.config.get("max_file_size_bytes", 1048576):
                        continue
                except OSError:
                    continue
                
                valid_files.append(file_path)
        return valid_files
