from __future__ import annotations

from typing import Any, Dict, Set
from plugins import LanguagePlugin


class JavaPlugin(LanguagePlugin):
    @property
    def language_id(self) -> str:
        return "java"

    @property
    def extensions(self) -> Set[str]:
        return {".java"}

    @property
    def tree_sitter_lang_name(self) -> str:
        return "java"

    def get_taint_signatures(self) -> Dict[str, Set[str]]:
        return {
            "sources": {
                "System.getenv", "System.getProperty", "request.getParameter", "request.getHeader",
                "Scanner.nextLine", "BufferedReader.readLine", "InputStream.read"
            },
            "sinks": {
                "Runtime.getRuntime().exec", "ProcessBuilder.start", "Statement.executeQuery",
                "Connection.prepareStatement", "InitialContext.lookup", "ObjectInputStream.readObject"
            },
            "propagators": {
                "StringBuilder.append", "StringBuffer.append", "String.concat", "String.format"
            },
            "sanitizers": {
                "PreparedStatement.setString", "PreparedStatement.setInt", "StringEscapeUtils.escapeHtml4",
                "URLEncoder.encode", "Pattern.compile"
            },
        }

    def is_function_node(self, node: Any) -> bool:
        return node.type in {"method_declaration", "constructor_declaration"}

    def extract_function_name(self, node: Any, code_bytes: bytes) -> str:
        for child in node.children:
            if child.type == "identifier":
                return code_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
        return "unknown_java_method"
