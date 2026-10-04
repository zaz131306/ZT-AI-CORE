"""Каскад валидации ответов (F-D-03): rules → similarity → NLI → fallback.

Порядок по возрастанию стоимости:
  1. rule-based (~0.1 мс): срабатывание → немедленная блокировка (fail fast);
  2. embedding-similarity (~5–20 мс):
       cos > 0.85 → ACCEPT (шаг 3 пропускается);
       0.60…0.85  → шаг 3;
       cos < 0.60 → немедленный FALLBACK;
  3. NLI (~50–200 мс): entailment → ACCEPT; contradiction → BLOCKED;
     neutral/низкий entailment → FALLBACK;
  4. результат (хэш ответа + вердикт) — в WORM (F-D-03 п.4).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from .nli import NliLabel, NliValidator
from .rules import rule_check
from .similarity import SimilarityBand, SimilarityValidator


class VerdictCode:
    ACCEPTED = "ACCEPTED"
    BLOCKED_PII = "BLOCKED_PII"
    BLOCKED_SECRET = "BLOCKED_SECRET"
    BLOCKED_PHRASE = "BLOCKED_PHRASE"
    LOW_SIMILARITY = "LOW_SIMILARITY"
    NLI_CONTRADICTION = "NLI_CONTRADICTION"
    NLI_NOT_ENTAILED = "NLI_NOT_ENTAILED"
    INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"
    EMPTY_RETRIEVAL = "EMPTY_RETRIEVAL"


class ValidatorStage:
    RULE_BASED = "RULE_BASED"
    EMBEDDING_SIMILARITY = "EMBEDDING_SIMILARITY"
    NLI = "NLI"
    FALLBACK = "FALLBACK"


@dataclass
class ValidatorTrace:
    """Соответствует rag.proto:ValidatorTrace."""
    decided_by: str = ValidatorStage.FALLBACK
    code: str = VerdictCode.INSUFFICIENT_CONTEXT
    rule_ms: float = 0.0
    embed_ms: float = 0.0
    nli_ms: float = 0.0
    cos_sim: float = 0.0
    nli_entailment: float = 0.0
    rule_hits: List[str] = field(default_factory=list)
    nli_skipped: bool = True

    @property
    def accepted(self) -> bool:
        return self.code == VerdictCode.ACCEPTED


_CATEGORY_TO_CODE = {
    "PII": VerdictCode.BLOCKED_PII,
    "SECRET": VerdictCode.BLOCKED_SECRET,
    "FORBIDDEN_PHRASE": VerdictCode.BLOCKED_PHRASE,
}


class CascadeValidator:
    def __init__(self, similarity: SimilarityValidator, nli: NliValidator,
                 nli_entail_threshold: float = 0.5,
                 extra_forbidden: Optional[List[str]] = None):
        self.similarity = similarity
        self.nli = nli
        self.nli_entail_threshold = nli_entail_threshold
        self.extra_forbidden = extra_forbidden or []

    def validate(self, answer: str, context_chunks: Sequence[str],
                 context_weights: Optional[Sequence[float]] = None
                 ) -> ValidatorTrace:
        trace = ValidatorTrace()

        # --- Уровень 1: rule-based (fail fast) --------------------------------
        t0 = time.perf_counter()
        rule_verdict = rule_check(answer, self.extra_forbidden)
        trace.rule_ms = (time.perf_counter() - t0) * 1000
        if rule_verdict.blocked:
            trace.decided_by = ValidatorStage.RULE_BASED
            first = rule_verdict.hits[0]
            trace.code = _CATEGORY_TO_CODE.get(first.category,
                                               VerdictCode.BLOCKED_PHRASE)
            trace.rule_hits = [f"{h.category}:{h.rule_id}" for h in rule_verdict.hits]
            return trace

        # --- Уровень 2: embedding similarity -----------------------------------
        t0 = time.perf_counter()
        sim_verdict = self.similarity.validate(answer, context_chunks, context_weights)
        trace.embed_ms = (time.perf_counter() - t0) * 1000
        trace.cos_sim = round(sim_verdict.cos_sim, 4)
        if sim_verdict.band == SimilarityBand.ACCEPT:
            trace.decided_by = ValidatorStage.EMBEDDING_SIMILARITY
            trace.code = VerdictCode.ACCEPTED
            trace.nli_skipped = True   # cos > 0.85 → шаг 3 пропускается (F-D-03)
            return trace
        if sim_verdict.band == SimilarityBand.REJECT:
            trace.decided_by = ValidatorStage.EMBEDDING_SIMILARITY
            trace.code = VerdictCode.LOW_SIMILARITY   # немедленный fallback
            return trace

        # --- Уровень 3: NLI (только пограничные случаи) -------------------------
        trace.nli_skipped = False
        t0 = time.perf_counter()
        nli_verdict = self.nli.validate(answer, context_chunks)
        trace.nli_ms = (time.perf_counter() - t0) * 1000
        trace.nli_entailment = nli_verdict.entailment
        trace.decided_by = ValidatorStage.NLI
        if nli_verdict.contradicts:
            trace.code = VerdictCode.NLI_CONTRADICTION
        elif (nli_verdict.label == NliLabel.ENTAILMENT
              and nli_verdict.entailment >= self.nli_entail_threshold):
            trace.code = VerdictCode.ACCEPTED
        else:
            trace.code = VerdictCode.NLI_NOT_ENTAILED
        return trace
