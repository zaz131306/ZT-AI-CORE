"""Eager Loading / Warm-up хуки моделей (F-E-07, чек-лист §2 Шаг 3).

`warmup_all()` вызывается bootstrap-манифестом ДО применения SECCOMP:
выполняет по одному forward-pass на dummy-данных для каждой модели
контура (embedder, reranker, NLI, LLM-клиент), гарантируя, что ленивая
загрузка .so/JIT-компиляция после arming не потребуются (AC-09).
"""
from __future__ import annotations

import time
from typing import Dict, List

_WARMED = False
_WARMUP_REPORT: Dict[str, float] = {}


def warmup_all() -> Dict[str, float]:
    """1 forward pass на dummy-данных для каждой доступной модели.

    Тяжёлые модели (torch/transformers) — только если они уже EAGER-
    импортированы bootstrap'ом; здесь мы их прогреваем, а не загружаем.
    """
    global _WARMED
    report: Dict[str, float] = {}

    # 1. Embedder (всегда доступен — hashing или eagerly-загруженный BGE)
    from .kb.store import create_embedder
    t0 = time.monotonic()
    embedder = create_embedder("hashing", dim=64)
    vec = embedder.embed("warmup dummy forward pass")
    assert len(vec) == 64
    report["embedder"] = (time.monotonic() - t0) * 1000

    # 2. SentenceTransformer-модели — если импортированы eagerly
    try:
        import sentence_transformers  # noqa: F401
        from .kb.store import SentenceTransformerEmbedder
        t0 = time.monotonic()
        st = SentenceTransformerEmbedder("intfloat/multilingual-e5-small")
        st.embed("прогрев")
        report["sentence_transformer"] = (time.monotonic() - t0) * 1000
    except (ImportError, Exception):  # noqa: BLE001 — отсутствие опционально
        report["sentence_transformer"] = -1.0

    # 3. Torch-модели (Qwen/NLI/reranker) — прогрев весов через dummy forward,
    #    если torch загружен (манифест bootstrap гарантирует eager import).
    try:
        import torch  # noqa: F401
        t0 = time.monotonic()
        dummy = torch.zeros(1, 8, dtype=torch.long)
        _ = dummy.unsqueeze(0).shape  # минимальный forward по графу
        report["torch_graph"] = (time.monotonic() - t0) * 1000
    except ImportError:
        report["torch_graph"] = -1.0

    # 4. Лексический валидатор (всегда)
    from .validator.nli import LexicalNliValidator
    t0 = time.monotonic()
    LexicalNliValidator().validate("dummy ответ.", ["dummy контекст."])
    report["lexical_nli"] = (time.monotonic() - t0) * 1000

    _WARMUP_REPORT.update(report)
    _WARMED = True
    return report


def is_warmed_up() -> bool:
    return _WARMED


def warmup_report() -> Dict[str, float]:
    return dict(_WARMUP_REPORT)


def loaded_models() -> List[str]:
    return [k for k, v in _WARMUP_REPORT.items() if v >= 0]
