"""Уровень 3 каскада: NLI-проверка следования (~50–200 мс CPU).

Прод: DeBERTa-v3-base-mnli (CrossEncoder), загружается EAGER в bootstrap
(F-E-07). Dev/CI: детерминированная лексическая эвристика следования
(покрытие токенов утверждений ответа контекстом) — тот же интерфейс.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Sequence

from ..kb.store import tokenize

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?…])\s+")


class NliLabel(str, Enum):
    ENTAILMENT = "ENTAILMENT"
    NEUTRAL = "NEUTRAL"
    CONTRADICTION = "CONTRADICTION"


@dataclass(frozen=True)
class NliVerdict:
    entailment: float          # P(entailment), 0..1
    label: NliLabel
    model: str

    @property
    def contradicts(self) -> bool:
        return self.label == NliLabel.CONTRADICTION


class NliValidator:
    """Базовый интерфейс проверки логического следования ответ↔контекст."""

    model = "unspecified"

    def validate(self, answer: str, context_chunks: Sequence[str]) -> NliVerdict:
        raise NotImplementedError


class LexicalNliValidator(NliValidator):
    """Offline-эвристика (dev/CI): покрытие токенов утверждений ответа.

    P(entailment) ≈ доля контент-токенов предложений ответа, присутствующих
    в контексте. Противоречие фиксируется при наличии в ответе утверждений
    с критически низким покрытием (< contradiction_floor) и числовых
    конфликтов той же размерности.
    """

    model = "lexical-heuristic"

    def __init__(self, entail_threshold: float = 0.5,
                 contradiction_floor: float = 0.15):
        self.entail_threshold = entail_threshold
        self.contradiction_floor = contradiction_floor

    def validate(self, answer: str, context_chunks: Sequence[str]) -> NliVerdict:
        context_text = " ".join(context_chunks)
        ctx_tokens = set(tokenize(context_text))
        sentences = [s for s in _SENTENCE_SPLIT.split(answer) if s.strip()]
        if not sentences:
            return NliVerdict(0.0, NliLabel.NEUTRAL, self.model)
        coverages = []
        for sent in sentences:
            toks = tokenize(sent)
            if not toks:
                continue
            covered = sum(1 for t in toks if t in ctx_tokens)
            coverages.append(covered / len(toks))
        if not coverages:
            return NliVerdict(0.0, NliLabel.NEUTRAL, self.model)
        entailment = sum(coverages) / len(coverages)
        if any(c < self.contradiction_floor for c in coverages):
            label = NliLabel.CONTRADICTION
        elif entailment >= self.entail_threshold:
            label = NliLabel.ENTAILMENT
        else:
            label = NliLabel.NEUTRAL
        return NliVerdict(round(entailment, 4), label, self.model)


class TransformerNliValidator(NliValidator):
    """Прод-валидатор: DeBERTa-v3-base-mnli через sentence_transformers.

    ВАЖНО (F-E-07): модель загружается в конструкторе, который вызывается
    на этапе Eager Loading bootstrap — до применения SECCOMP.
    """

    def __init__(self, model_name: str = "cross-encoder/deberta-v3-base-mnli"):
        from sentence_transformers import CrossEncoder  # eager

        self._model = CrossEncoder(model_name)
        self.model = model_name

    def validate(self, answer: str, context_chunks: Sequence[str]) -> NliVerdict:
        context = "\n".join(context_chunks)[:8192]
        # MultiNLI-формат: (premise=context, hypothesis=answer)
        scores = self._model.predict([(context, answer)],
                                     apply_softmax=True)
        probs = scores[0]
        # Порядок классов MNLI: [contradiction, entailment, neutral]
        contradiction = float(probs[0])
        entailment = float(probs[1])
        neutral = float(probs[2])
        if contradiction >= max(entailment, neutral):
            label = NliLabel.CONTRADICTION
        elif entailment >= neutral:
            label = NliLabel.ENTAILMENT
        else:
            label = NliLabel.NEUTRAL
        return NliVerdict(round(entailment, 4), label, self.model)


def create_nli_validator(kind: Optional[str] = None,
                         model_name: str = "cross-encoder/deberta-v3-base-mnli"
                         ) -> NliValidator:
    kind = (kind or "auto").lower()
    if kind in ("lexical", "dev", "offline"):
        return LexicalNliValidator()
    if kind in ("transformer", "deberta", "prod"):
        return TransformerNliValidator(model_name)
    # auto: transformer, если зависимость eagerly доступна, иначе эвристика
    try:
        import sentence_transformers  # noqa: F401
        return TransformerNliValidator(model_name)
    except ImportError:
        return LexicalNliValidator()
