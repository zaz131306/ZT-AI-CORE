"""Гибридный retriever: вектор + BM25 → RRF → Cross-Encoder rerank.

NF-01: поиск + rerank ≤ 1.5 с (без LLM). Ограничение top_k (ZT_RAG_TOP_K_MAX)
— контрмера Model Extraction (Раздел 2.2).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol, Sequence

from ..kb.bm25 import Bm25Index
from ..kb.store import Embedder, StoredChunk, VectorStore


@dataclass
class ScoredChunk:
    """Соответствует rag.proto:ScoredChunk."""
    chunk: StoredChunk
    vector_score: float = 0.0
    bm25_score: float = 0.0
    rrf_score: float = 0.0
    rerank_score: Optional[float] = None
    final_rank: int = 0

    @property
    def final_score(self) -> float:
        return self.rerank_score if self.rerank_score is not None else self.rrf_score


class Reranker(Protocol):
    name: str

    def rerank(self, query: str, chunks: Sequence[StoredChunk]) -> List[float]: ...


class CrossEncoderReranker:
    """Прод-reranker (F-B-04): sentence_transformers CrossEncoder.

    Модель загружается EAGER в bootstrap (F-E-07); lazy-импорт запрещён.
    """

    def __init__(self, model_name: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"):
        from sentence_transformers import CrossEncoder

        self._model = CrossEncoder(model_name)
        self.name = model_name

    def rerank(self, query: str, chunks: Sequence[StoredChunk]) -> List[float]:
        pairs = [[query, c.text] for c in chunks]
        scores = self._model.predict(pairs)
        return [float(s) for s in scores]


class LexicalOverlapReranker:
    """Offline-reranker (dev/CI): доля токенов запроса, покрытая чанком.

    Анти-bridging правило: одиночное совпадение токена (особенно числового,
    напр. «(вариант 0)» ↔ «TPM 2.0») НЕ является релевантностью, если оно
    покрывает < 50% запроса. Скор 0, если совпавших токенов < 2 И покрытие
    < 0.5. Детерминирован, не требует моделей.
    """

    name = "lexical-overlap"
    MIN_OVERLAP_TOKENS = 2
    MIN_SINGLE_COVERAGE = 0.5

    def rerank(self, query: str, chunks: Sequence[StoredChunk]) -> List[float]:
        from ..kb.store import tokenize

        q_tokens = set(tokenize(query))
        if not q_tokens:
            return [0.0 for _ in chunks]
        scores = []
        for chunk in chunks:
            c_tokens = set(tokenize(chunk.text))
            overlap = len(q_tokens & c_tokens)
            coverage = overlap / len(q_tokens)
            if overlap >= self.MIN_OVERLAP_TOKENS or coverage >= self.MIN_SINGLE_COVERAGE:
                scores.append(coverage)
            else:
                scores.append(0.0)  # токен-мост (числа/предлоги) — не релевантность
        return scores


@dataclass
class RetrievalResult:
    scored: List[ScoredChunk]
    latency_ms: float
    embedder_id: str
    reranker_applied: bool


class HybridRetriever:
    def __init__(self, store: VectorStore, embedder: Embedder,
                 bm25: Bm25Index, rrf_k: int = 60,
                 reranker: Optional[Reranker] = None):
        self.store = store
        self.embedder = embedder
        self.bm25 = bm25
        self.rrf_k = rrf_k
        self.reranker = reranker

    def reindex_bm25(self) -> None:
        self.bm25.build(self.store.all_chunks())

    def retrieve(self, query: str, top_k: int, top_k_max: int = 8,
                 min_score: float = 0.0, candidate_multiplier: int = 4
                 ) -> RetrievalResult:
        started = time.monotonic()
        top_k = max(1, min(top_k, top_k_max))
        pool = top_k * candidate_multiplier

        # 1. Векторный поиск
        qvec = self.embedder.embed(query)
        vector_hits = self.store.search(qvec, pool)
        vector_rank: Dict[str, int] = {
            c.chunk_id: i for i, (c, _s) in enumerate(vector_hits)}
        vector_score: Dict[str, float] = {c.chunk_id: s for c, s in vector_hits}

        # 2. BM25
        bm25_hits = self.bm25.top(query, pool)
        bm25_rank: Dict[str, int] = {cid: i for i, (cid, _s) in enumerate(bm25_hits)}
        bm25_score: Dict[str, float] = {cid: s for cid, s in bm25_hits}

        # 3. RRF-слияние (Reciprocal Rank Fusion)
        all_ids = set(vector_rank) | set(bm25_rank)
        by_id: Dict[str, StoredChunk] = {c.chunk_id: c for c, _ in vector_hits}
        if not all_ids <= set(by_id):
            for chunk in self.store.all_chunks():
                by_id.setdefault(chunk.chunk_id, chunk)
        fused: List[ScoredChunk] = []
        for cid in all_ids:
            chunk = by_id.get(cid)
            if chunk is None:
                continue
            rrf = 0.0
            if cid in vector_rank:
                rrf += 1.0 / (self.rrf_k + vector_rank[cid] + 1)
            if cid in bm25_rank:
                rrf += 1.0 / (self.rrf_k + bm25_rank[cid] + 1)
            fused.append(ScoredChunk(
                chunk=chunk,
                vector_score=vector_score.get(cid, 0.0),
                bm25_score=bm25_score.get(cid, 0.0),
                rrf_score=rrf,
            ))
        fused.sort(key=lambda sc: sc.rrf_score, reverse=True)

        # 4. Reranking (Cross-Encoder или offline-эвристика)
        candidates = fused[:pool]
        reranked_applied = False
        if self.reranker is not None and candidates:
            scores = self.reranker.rerank(query, [sc.chunk for sc in candidates])
            for sc, rs in zip(candidates, scores):
                sc.rerank_score = rs
            candidates.sort(key=lambda sc: sc.final_score, reverse=True)
            reranked_applied = True

        # 5. Фильтр min_score + ограничение top_k (anti Model Extraction)
        results = [sc for sc in candidates if sc.final_score >= min_score][:top_k]
        for rank, sc in enumerate(results, start=1):
            sc.final_rank = rank

        latency = (time.monotonic() - started) * 1000
        return RetrievalResult(scored=results, latency_ms=latency,
                               embedder_id=self.embedder.name,
                               reranker_applied=reranked_applied)
