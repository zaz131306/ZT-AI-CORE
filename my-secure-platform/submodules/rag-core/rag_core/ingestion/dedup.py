"""Дедупликация по криптографическому хэшу (F-A-04, anti Data Poisoning).

Хэш документа/чанка — BLAKE3 (канонический для контура, Приложение Б);
fallback hashlib.blake2b только если пакет blake3 не eagerly-загружен.
Повторная загрузка источника с тем же контентом отклоняется как DUPLICATE.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set

try:  # Eager-загрузка в bootstrap (F-E-07)
    import blake3 as _blake3

    def content_hash(data: bytes) -> str:
        return _blake3.blake3(data).hexdigest()

    HASH_ALGO = "blake3"
except ImportError:  # pragma: no cover - dev без blake3
    import hashlib

    def content_hash(data: bytes) -> str:
        return "blake2b:" + hashlib.blake2b(data, digest_size=32).hexdigest()

    HASH_ALGO = "blake2b(fallback)"


def hash_text(text: str) -> str:
    return content_hash(text.encode("utf-8"))


@dataclass(frozen=True)
class DedupDecision:
    is_duplicate: bool
    content_hash: str
    first_doc_id: Optional[str] = None


class DedupRegistry:
    """Реестр хэшей документов и чанков (потокобезопасен)."""

    def __init__(self) -> None:
        self._docs: Dict[str, str] = {}     # hash -> doc_id
        self._chunks: Set[str] = set()      # хэши чанков
        self._lock = threading.Lock()
        self.skipped_duplicates = 0

    def check_document(self, doc_id: str, text: str) -> DedupDecision:
        h = hash_text(text)
        with self._lock:
            existing = self._docs.get(h)
            if existing is not None:
                self.skipped_duplicates += 1
                return DedupDecision(True, h, existing)
            self._docs[h] = doc_id
            return DedupDecision(False, h, None)

    def check_chunk(self, text: str) -> DedupDecision:
        h = hash_text(text)
        with self._lock:
            if h in self._chunks:
                self.skipped_duplicates += 1
                return DedupDecision(True, h, None)
            self._chunks.add(h)
            return DedupDecision(False, h, None)

    def known_hashes(self) -> List[str]:
        with self._lock:
            return list(self._docs.keys())

    def state(self) -> dict:
        with self._lock:
            return {"documents": dict(self._docs),
                    "chunks": sorted(self._chunks),
                    "skipped_duplicates": self.skipped_duplicates}

    def load_state(self, state: dict) -> None:
        with self._lock:
            self._docs = dict(state.get("documents", {}))
            self._chunks = set(state.get("chunks", []))
            self.skipped_duplicates = int(state.get("skipped_duplicates", 0))

    def remove_document(self, text_hashes: Iterable[str]) -> None:
        with self._lock:
            for h in text_hashes:
                self._docs.pop(h, None)
