from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import numpy as np
from huggingface_hub import hf_hub_download, list_repo_files
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams
from sentence_transformers import SentenceTransformer


_RE_C_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_RE_C_LINE_COMMENT = re.compile(r"//[^\n]*")
_RE_NON_ASCII = re.compile(r"[^\x00-\x7F]")

MIN_CODE_TOKENS = 10
MAX_CODE_TOKENS = 512


def _strip_c_like_comments(text: str) -> str:
    text = _RE_C_BLOCK_COMMENT.sub(" ", text)
    text = _RE_C_LINE_COMMENT.sub("", text)
    return text


def _remove_non_ascii(text: str) -> str:
    return _RE_NON_ASCII.sub(" ", text)


def _normalize_whitespace(text: str) -> str:
    return " ".join(text.split()).strip()


def _token_count(text: str) -> int:
    return len(re.findall(r"\w+|[^\w\s]", text))


def _normalize_cwe(raw: Any) -> str:
    if raw is None:
        return "Unknown"
    if isinstance(raw, list):
        if not raw:
            return "Unknown"
        raw = raw[0]
    value = str(raw).strip()
    if not value:
        return "Unknown"
    if value.isdigit():
        return f"CWE-{value}"
    return value


def _normalize_cve(raw: Any) -> str:
    if raw is None:
        return "Unknown"
    value = str(raw).strip()
    if re.match(r"^CVE-\d{4}-\d+$", value, flags=re.IGNORECASE):
        return value.upper()
    return "Unknown"


def _content_hash(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()


def build_embedding_text(text: str, cwe: str, cve: str, source: str) -> str:
    header = f"[{cwe} | {cve} | {source}]"
    words = text.split()
    if len(words) > 400:
        text = " ".join(words[:400]) + " ..."
    return f"{header}\n{text}"


def _preprocess_record(
    raw_text: str,
    cwe_raw: Any,
    cve_raw: Any,
    source: str,
    *,
    strip_comments: bool,
    min_tokens: int,
    max_tokens: int,
) -> Optional[Dict[str, Any]]:
    if not isinstance(raw_text, str) or not raw_text.strip():
        return None

    cleaned = _remove_non_ascii(raw_text)
    if strip_comments:
        cleaned = _strip_c_like_comments(cleaned)
    cleaned = _normalize_whitespace(cleaned)

    tokens = _token_count(cleaned)
    if tokens < min_tokens or tokens > max_tokens:
        return None

    cwe = _normalize_cwe(cwe_raw)
    cve = _normalize_cve(cve_raw)
    embedding_text = build_embedding_text(cleaned, cwe, cve, source)

    return {
        "cleaned_text": cleaned,
        "cwe": cwe,
        "cve": cve,
        "embedding_text": embedding_text,
        "token_count": tokens,
        "content_hash": _content_hash(cleaned),
    }


class RAGEngine:
    def __init__(self, model: SentenceTransformer, repo_id: str = "starsofchance/PrimeVul"):
        self.model = model
        self.repo_id = repo_id

        self.max_primevul_records = int(os.getenv("RAG_MAX_PRIMEVUL_RECORDS", "0"))
        self.nvd_live_enabled = os.getenv("RAG_NVD_LIVE_ENABLED", "1") == "1"
        self.nvd_api_key = os.getenv("NVD_API_KEY", "")
        self.nvd_results_per_page = max(1, min(2000, int(os.getenv("RAG_NVD_RESULTS_PER_PAGE", "2000"))))
        self.nvd_pages = max(1, int(os.getenv("RAG_NVD_PAGES", "2")))
        self.nvd_days_back = max(1, int(os.getenv("RAG_NVD_DAYS_BACK", "365")))

        self.qdrant_url = os.getenv("RAG_QDRANT_URL", "http://localhost:6333")
        self.qdrant_api_key = os.getenv("RAG_QDRANT_API_KEY", "")
        self.collection_name = os.getenv("RAG_QDRANT_COLLECTION", "code_forensics_knowledge")
        self.qdrant_timeout_sec = float(os.getenv("RAG_QDRANT_TIMEOUT_SEC", "30"))

        self.entries: List[Dict[str, Any]] = []
        self.local_vectors: Optional[np.ndarray] = None
        self.qdrant: Optional[QdrantClient] = None
        self.vector_size = int(model.get_sentence_embedding_dimension())

        self.refresh()

    def refresh(self) -> Dict[str, int]:
        self.entries = []
        self._load_entries()

        if not self.entries:
            self.local_vectors = None
            return {"entries": 0}

        texts = [item["embedding_text"] for item in self.entries]
        vectors = self.model.encode(texts, normalize_embeddings=True, show_progress_bar=True)
        self.local_vectors = np.array(vectors, dtype="float32")

        self._initialize_qdrant()
        if self.qdrant is not None:
            self._upsert_entries_to_qdrant()

        return {"entries": len(self.entries)}

    def _load_entries(self):
        self.entries.extend(self._load_primevul())
        self.entries.extend(self._load_knowledge_directory())
        if self.nvd_live_enabled:
            self.entries.extend(self._load_nvd_live())

        # Global deduplication across all sources while retaining label context.
        deduped: List[Dict[str, Any]] = []
        seen_keys = set()
        for entry in self.entries:
            dedupe_key = (
                entry.get("content_hash") or _content_hash(entry.get("embedding_text", "")),
                entry.get("source"),
                entry.get("type"),
                entry.get("cwe"),
                entry.get("cve"),
            )
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            deduped.append(entry)
        self.entries = deduped

    def _load_primevul(self) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        seen_hashes = set()
        stats: Counter = Counter()
        try:
            files = list_repo_files(repo_id=self.repo_id, repo_type="dataset")
            data_file = next((f for f in files if f.endswith(".jsonl") and "file_info" not in f), None)
            if data_file is None:
                return records

            local_path = hf_hub_download(repo_id=self.repo_id, filename=data_file, repo_type="dataset")
            with open(local_path, "r", encoding="utf-8") as handle:
                for line_idx, line in enumerate(handle):
                    if self.max_primevul_records > 0 and line_idx >= self.max_primevul_records:
                        break
                    try:
                        row = json.loads(line)
                    except Exception:
                        stats["parse_error"] += 1
                        continue

                    raw_code = row.get("func") or row.get("code")
                    target = row.get("target")
                    label = row.get("label")
                    is_vuln = (
                        target == 1 or target == "1" or target is True or
                        label == 1 or label == "1" or label is True
                    )
                    if not is_vuln:
                        stats["benign_skipped"] += 1
                        continue

                    preprocessed = _preprocess_record(
                        raw_text=raw_code or "",
                        cwe_raw=row.get("cwe"),
                        cve_raw=row.get("cve"),
                        source="PrimeVul",
                        strip_comments=True,
                        min_tokens=MIN_CODE_TOKENS,
                        max_tokens=MAX_CODE_TOKENS,
                    )
                    if preprocessed is None:
                        stats["filtered_length"] += 1
                        continue

                    record_hash = preprocessed["content_hash"]
                    if record_hash in seen_hashes:
                        stats["duplicate"] += 1
                        continue
                    seen_hashes.add(record_hash)

                    records.append(
                        {
                            "source": "PrimeVul",
                            "type": "code",
                            "embedding_text": preprocessed["embedding_text"],
                            "cwe": preprocessed["cwe"],
                            "cve": preprocessed["cve"],
                            "token_count": preprocessed["token_count"],
                            "content_hash": record_hash,
                            "metadata": {
                                "project": row.get("project", "Unknown"),
                                "commit_id": row.get("commit_id", "Unknown"),
                            },
                        }
                    )
                    stats["accepted"] += 1
        except Exception:
            return records

        if records:
            print(
                "[RAG] PrimeVul: "
                f"loaded={stats['accepted']} | "
                f"benign_skipped={stats['benign_skipped']} | "
                f"filtered_length={stats['filtered_length']} | "
                f"duplicates={stats['duplicate']}"
            )

        return records

    def _load_knowledge_directory(self) -> List[Dict[str, Any]]:
        knowledge: List[Dict[str, Any]] = []
        knowledge_dir = os.path.join(os.getcwd(), "knowledge")
        if not os.path.isdir(knowledge_dir):
            return knowledge

        for file_name in sorted(os.listdir(knowledge_dir)):
            if file_name == "nvd_live.json":
                continue
            if not (file_name.endswith(".json") or file_name.endswith(".jsonl")):
                continue

            path = os.path.join(knowledge_dir, file_name)
            try:
                if path.endswith(".jsonl"):
                    with open(path, "r", encoding="utf-8") as handle:
                        for line in handle:
                            row = json.loads(line)
                            normalized = self._normalize_knowledge_item(row)
                            if normalized:
                                knowledge.append(normalized)
                    continue

                with open(path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)

                if isinstance(payload, list):
                    for item in payload:
                        normalized = self._normalize_knowledge_item(item)
                        if normalized:
                            knowledge.append(normalized)
                elif isinstance(payload, dict):
                    normalized = self._normalize_knowledge_item(payload)
                    if normalized:
                        knowledge.append(normalized)
            except Exception as exc:
                print(f"[RAG] Skipping invalid knowledge file {file_name}: {exc}")
                continue

        if knowledge:
            print(f"[RAG] Knowledge files loaded: {len(knowledge)} entries")

        return knowledge

    def _normalize_knowledge_item(self, item: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(item, dict):
            return None

        raw_text = item.get("embedding_text") or item.get("text") or item.get("description")
        if not isinstance(raw_text, str) or not raw_text.strip():
            return None

        source = item.get("source", "Knowledge")
        entry_type = item.get("type", "concept")
        min_tokens = MIN_CODE_TOKENS if entry_type == "code" else 3
        preprocessed = _preprocess_record(
            raw_text=raw_text,
            cwe_raw=item.get("cwe"),
            cve_raw=item.get("cve"),
            source=source,
            strip_comments=entry_type == "code",
            min_tokens=min_tokens,
            max_tokens=MAX_CODE_TOKENS,
        )
        if preprocessed is None:
            return None

        extra_metadata = {
            key: value
            for key, value in item.items()
            if key not in {"source", "type", "embedding_text", "text", "description", "cwe", "cve", "metadata"}
        }

        metadata = item.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        if extra_metadata:
            metadata = {**metadata, **extra_metadata}

        return {
            "source": source,
            "type": entry_type,
            "embedding_text": preprocessed["embedding_text"],
            "cwe": preprocessed["cwe"],
            "cve": preprocessed["cve"],
            "token_count": preprocessed["token_count"],
            "content_hash": preprocessed["content_hash"],
            "metadata": metadata,
        }

    def _load_nvd_live(self) -> List[Dict[str, Any]]:
        loaded: List[Dict[str, Any]] = []

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=self.nvd_days_back)
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        page_start_index = 0

        try:
            pub_start = start_time.strftime("%Y-%m-%dT%H:%M:%S.000") + "Z"
            pub_end = end_time.strftime("%Y-%m-%dT%H:%M:%S.000") + "Z"

            for _ in range(self.nvd_pages):
                params = {
                    "startIndex": page_start_index,
                    "resultsPerPage": self.nvd_results_per_page,
                    "pubStartDate": pub_start,
                    "pubEndDate": pub_end,
                }
                request_url = f"{base_url}?{urllib.parse.urlencode(params)}"
                headers = {"User-Agent": "tree-sitter-demo-rag/1.0"}
                if self.nvd_api_key:
                    headers["apiKey"] = self.nvd_api_key

                request = urllib.request.Request(request_url, headers=headers)
                try:
                    with urllib.request.urlopen(request, timeout=30) as response:
                        payload = json.loads(response.read().decode("utf-8"))
                except urllib.error.HTTPError as http_exc:
                    if http_exc.code == 404:
                        print(f"[RAG] NVD 404 for date range {pub_start} - {pub_end}; skipping live fetch")
                        break
                    else:
                        raise

                vulnerabilities = payload.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "Unknown")

                    descriptions = cve.get("descriptions", [])
                    english_description = ""
                    for desc in descriptions:
                        if desc.get("lang") == "en" and isinstance(desc.get("value"), str):
                            english_description = desc["value"].strip()
                            break
                    if not english_description:
                        continue

                    cwe_value = "Unknown"
                    for weakness in cve.get("weaknesses", []):
                        for desc in weakness.get("description", []):
                            value = str(desc.get("value", ""))
                            if "CWE-" in value:
                                cwe_value = value
                                break
                        if cwe_value != "Unknown":
                            break

                    preprocessed = _preprocess_record(
                        raw_text=f"{cve_id}: {english_description}",
                        cwe_raw=cwe_value,
                        cve_raw=cve_id,
                        source="NVDLive",
                        strip_comments=False,
                        min_tokens=3,
                        max_tokens=MAX_CODE_TOKENS,
                    )
                    if preprocessed is None:
                        continue

                    loaded.append(
                        {
                            "source": "NVDLive",
                            "type": "cve_description",
                            "embedding_text": preprocessed["embedding_text"],
                            "cwe": preprocessed["cwe"],
                            "cve": preprocessed["cve"],
                            "token_count": preprocessed["token_count"],
                            "content_hash": preprocessed["content_hash"],
                            "metadata": {
                                "published": cve.get("published", "Unknown"),
                                "last_modified": cve.get("lastModified", "Unknown"),
                            },
                        }
                    )

                page_start_index += self.nvd_results_per_page
                total_results = int(payload.get("totalResults", 0))
                if page_start_index >= total_results:
                    break

            cache_path = os.path.join(os.getcwd(), "knowledge", "nvd_live.json")
            with open(cache_path, "w", encoding="utf-8") as handle:
                json.dump(loaded, handle, ensure_ascii=False, indent=2)

            if loaded:
                print(f"[RAG] NVD live loaded: {len(loaded)} entries")
            else:
                print("[RAG] NVD live returned 0 entries")
        except Exception as exc:
            print(f"[RAG] NVD live fetch failed ({exc}); continuing with local knowledge files")

        return loaded

    def _initialize_qdrant(self):
        try:
            self.qdrant = QdrantClient(
                url=self.qdrant_url,
                api_key=self.qdrant_api_key or None,
                timeout=self.qdrant_timeout_sec,
            )
            exists = self._collection_exists(self.collection_name)
            if not exists:
                self.qdrant.create_collection(
                    collection_name=self.collection_name,
                    vectors_config=VectorParams(size=self.vector_size, distance=Distance.COSINE),
                )
            elif os.getenv("RAG_REBUILD", "0") == "1":
                self.qdrant.recreate_collection(
                    collection_name=self.collection_name,
                    vectors_config=VectorParams(size=self.vector_size, distance=Distance.COSINE),
                )
        except Exception as exc:
            print(f"[RAG] Qdrant unavailable ({exc}); using in-process fallback search")
            self.qdrant = None

    def _collection_exists(self, collection_name: str) -> bool:
        if self.qdrant is None:
            return False

        if hasattr(self.qdrant, "collection_exists"):
            try:
                return bool(self.qdrant.collection_exists(collection_name))
            except Exception:
                return False

        try:
            collections = self.qdrant.get_collections().collections
            return any(item.name == collection_name for item in collections)
        except Exception:
            return False

    def _upsert_entries_to_qdrant(self):
        if self.qdrant is None or self.local_vectors is None:
            return

        points: List[PointStruct] = []
        for idx, entry in enumerate(self.entries):
            payload = {
                "source": entry.get("source", "Unknown"),
                "type": entry.get("type", "concept"),
                "embedding_text": entry.get("embedding_text", ""),
                "cwe": entry.get("cwe", "Unknown"),
                "cve": entry.get("cve", "Unknown"),
                "metadata": entry.get("metadata", {}),
            }
            points.append(
                PointStruct(
                    id=idx,
                    vector=self.local_vectors[idx].tolist(),
                    payload=payload,
                )
            )

        batch_size = 256
        for i in range(0, len(points), batch_size):
            self.qdrant.upsert(
                collection_name=self.collection_name,
                points=points[i : i + batch_size],
                wait=True,
            )

        print(f"[RAG] Qdrant collection synced: {len(points)} entries")

    def search(self, query_text: str, top_k: int = 3) -> List[Dict[str, Any]]:
        if not self.entries:
            return []

        safe_top_k = max(1, min(top_k, len(self.entries)))
        query_vector = np.array(
            self.model.encode([query_text], normalize_embeddings=True),
            dtype="float32",
        )

        if self.qdrant is not None:
            try:
                if hasattr(self.qdrant, "query_points"):
                    query_result = self.qdrant.query_points(
                        collection_name=self.collection_name,
                        query=query_vector[0].tolist(),
                        limit=safe_top_k,
                        with_payload=True,
                    )
                    points = getattr(query_result, "points", query_result)
                else:
                    points = self.qdrant.search(
                        collection_name=self.collection_name,
                        query_vector=query_vector[0].tolist(),
                        limit=safe_top_k,
                        with_payload=True,
                    )
                results: List[Dict[str, Any]] = []
                for point in points:
                    payload = point.payload or {}
                    score = float(getattr(point, "score", 0.0))
                    results.append(
                        {
                            "source": payload.get("source", "Unknown"),
                            "type": payload.get("type", "concept"),
                            "embedding_text": payload.get("embedding_text", ""),
                            "cwe": payload.get("cwe", "Unknown"),
                            "cve": payload.get("cve", "Unknown"),
                            "metadata": payload.get("metadata", {}),
                            "confidence": round(max(0.0, min(1.0, score)), 4),
                        }
                    )
                return results
            except Exception as exc:
                print(f"[RAG] Qdrant search failed ({exc}); using local fallback")

        if self.local_vectors is None:
            return []

        scores = (self.local_vectors @ query_vector.T).reshape(-1)
        indices = np.argsort(-scores)[:safe_top_k]

        results: List[Dict[str, Any]] = []
        for idx in indices:
            int_idx = int(idx)
            if 0 <= int_idx < len(self.entries):
                entry = self.entries[int_idx]
                confidence = float(scores[int_idx])
                results.append(
                    {
                        "source": entry.get("source", "Unknown"),
                        "type": entry.get("type", "concept"),
                        "embedding_text": entry.get("embedding_text", ""),
                        "cwe": entry.get("cwe", "Unknown"),
                        "cve": entry.get("cve", "Unknown"),
                        "metadata": entry.get("metadata", {}),
                        "confidence": round(max(0.0, min(1.0, confidence)), 4),
                    }
                )
        return results
