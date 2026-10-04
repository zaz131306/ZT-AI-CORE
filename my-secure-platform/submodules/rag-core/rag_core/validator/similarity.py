"""Уровень 2 каскада: embedding-similarity (~5–20 мс CPU).

Пороги F-D-03:
  cos_sim > 0.85             → ответ принят, уровень 3 пропускается;
  0.60 ≤ cos_sim ≤ 0.85      → передача на NLI (уровень 3);
  cos_sim < 0.60             → немедленный fallback.

Гранулярность сравнения: ответ (обычно 1–2 предложения) сравнивается
И с полными чанками, И с их предложениями. Без расширения предложение,
дословно извлечённое из чанка, получало бы заниженный cos из-за
разницы длин векторов (dilution) — ложный LOW_SIMILARITY.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Sequence, Tuple

from ..kb.store import Embedder, cosine

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?…])\s+")


class SimilarityBand(str, Enum):
    ACCEPT = "ACCEPT"        # > cos_accept
    BORDERLINE = "BORDERLINE"  # [cos_reject, cos_accept]
    REJECT = "REJECT"        # < cos_reject


@dataclass(frozen=True)
class SimilarityVerdict:
    cos_sim: float
    band: SimilarityBand


def classify(cos_sim: float, cos_accept: float = 0.85,
             cos_reject: float = 0.60) -> SimilarityBand:
    if cos_sim > cos_accept:
        return SimilarityBand.ACCEPT
    if cos_sim < cos_reject:
        return SimilarityBand.REJECT
    return SimilarityBand.BORDERLINE


class SimilarityValidator:
    """Косинусное расстояние ответ↔контекст (агрегация по лучшим чанкам)."""

    def __init__(self, embedder: Embedder, cos_accept: float = 0.85,
                 cos_reject: float = 0.60):
        if cos_reject >= cos_accept:
            raise ValueError("cos_reject должен быть < cos_accept (F-D-03)")
        self.embedder = embedder
        self.cos_accept = cos_accept
        self.cos_reject = cos_reject

    def score(self, answer: str, context_chunks: Sequence[str],
              weights: Sequence[float] | None = None) -> float:
        """Агрегированная близость: max по чанкам И их предложениям.

        Семантика: ответ ДОЛЖЕН опираться хотя бы на один фрагмент контекста;
        максимум — консервативная агрегация для галлюцинаций (ответ «ни о чём»
        даёт низкий максимум).
        """
        if not context_chunks or not answer.strip():
            return 0.0
        ans_vec = self.embedder.embed(answer)
        fragments: List[Tuple[str, float]] = []
        for i, chunk in enumerate(context_chunks):
            weight = 1.0
            if weights is not None and i < len(weights):
                weight = max(0.0, min(1.0, float(weights[i])))
            fragments.append((chunk, weight))
            for sent in _SENTENCE_SPLIT.split(chunk):
                sent = sent.strip()
                # короткие фрагменты (< 3 слов) не расширяем — шум
                if len(sent) > 12 and sent != chunk:
                    fragments.append((sent, weight))
        best = 0.0
        if fragments:
            frag_vecs = self.embedder.embed_batch([f for f, _ in fragments])
            for (frag, weight), vec in zip(fragments, frag_vecs):
                sim = cosine(ans_vec, vec) * weight
                if sim > best:
                    best = sim
        return best

    def validate(self, answer: str, context_chunks: Sequence[str],
                 weights: Sequence[float] | None = None) -> SimilarityVerdict:
        sim = self.score(answer, context_chunks, weights)
        return SimilarityVerdict(
            cos_sim=sim,
            band=classify(sim, self.cos_accept, self.cos_reject))
