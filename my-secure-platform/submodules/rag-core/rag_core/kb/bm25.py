"""BM25 (Okapi) для гибридного поиска (F-B-03)."""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple

from .store import StoredChunk, tokenize


@dataclass
class Bm25Index:
    k1: float = 1.5
    b: float = 0.75
    _doc_tokens: List[List[str]] = field(default_factory=list, repr=False)
    _doc_ids: List[str] = field(default_factory=list, repr=False)
    _df: Dict[str, int] = field(default_factory=dict, repr=False)
    _avg_len: float = 0.0

    def build(self, chunks: Iterable[StoredChunk]) -> None:
        self._doc_tokens = []
        self._doc_ids = []
        self._df = {}
        total_len = 0
        for chunk in chunks:
            toks = tokenize(chunk.text)
            self._doc_tokens.append(toks)
            self._doc_ids.append(chunk.chunk_id)
            total_len += len(toks)
            for term in set(toks):
                self._df[term] = self._df.get(term, 0) + 1
        self._avg_len = (total_len / len(self._doc_tokens)) if self._doc_tokens else 0.0

    def __len__(self) -> int:
        return len(self._doc_ids)

    def score(self, query: str) -> List[Tuple[str, float]]:
        """Скоры всех документов для запроса (отсортированные по убыванию)."""
        if not self._doc_tokens:
            return []
        q_tokens = tokenize(query)
        if not q_tokens:
            return []
        n_docs = len(self._doc_tokens)
        results: List[Tuple[str, float]] = []
        for idx, toks in enumerate(self._doc_tokens):
            if not toks:
                continue
            tf_map = Counter(toks)
            doc_len = len(toks)
            score = 0.0
            for term in q_tokens:
                tf = tf_map.get(term, 0)
                if tf == 0:
                    continue
                df = self._df.get(term, 0)
                idf = math.log((n_docs - df + 0.5) / (df + 0.5) + 1.0)
                denom = tf + self.k1 * (1 - self.b + self.b * doc_len / (self._avg_len or 1.0))
                score += idf * (tf * (self.k1 + 1)) / denom
            if score > 0:
                results.append((self._doc_ids[idx], score))
        results.sort(key=lambda p: p[1], reverse=True)
        return results

    def top(self, query: str, k: int) -> List[Tuple[str, float]]:
        return self.score(query)[:max(0, k)]
