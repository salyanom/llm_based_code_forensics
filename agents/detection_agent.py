from __future__ import annotations

from typing import Any, Dict, List

from services.parser_service import ParserService


class DetectionAgent:
    def __init__(self, parser_service: ParserService):
        self.parser_service = parser_service

    def scan_folder(self, folder: str) -> List[Dict[str, Any]]:
        return self.parser_service.extract_functions_from_folder(folder)
