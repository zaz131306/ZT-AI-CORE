"""Конфигурация RAG-ядра (env ZT_RAG_*)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


@dataclass
class IngestionConfig:
    chunk_min_tokens: int = field(default_factory=lambda: _env_int("ZT_RAG_CHUNK_MIN", 300))
    chunk_max_tokens: int = field(default_factory=lambda: _env_int("ZT_RAG_CHUNK_MAX", 512))
    # Жёсткий предел ТЗ: 800 токенов (F-A-03)
    chunk_hard_max: int = 800
    overlap_ratio: float = field(default_factory=lambda: _env_float("ZT_RAG_OVERLAP", 0.125))
    overlap_min: float = 0.10
    overlap_max: float = 0.15
    dedup_by_hash: bool = True
    require_source_signature: bool = field(
        default_factory=lambda: _env("ZT_RAG_REQUIRE_SIG", "0") == "1")

    def validate(self) -> List[str]:
        problems: List[str] = []
        if not (self.chunk_min_tokens <= self.chunk_max_tokens <= self.chunk_hard_max):
            problems.append(
                f"чанкинг вне диапазона ТЗ: min={self.chunk_min_tokens} "
                f"max={self.chunk_max_tokens} (допустимо ≤ {self.chunk_hard_max})")
        if not (self.overlap_min <= self.overlap_ratio <= self.overlap_max):
            problems.append(
                f"overlap_ratio={self.overlap_ratio} вне диапазона 10–15% (F-A-03)")
        return problems


@dataclass
class RetrievalConfig:
    top_k: int = field(default_factory=lambda: _env_int("ZT_RAG_TOP_K", 5))
    top_k_max: int = field(default_factory=lambda: _env_int("ZT_RAG_TOP_K_MAX", 8))
    min_score: float = field(default_factory=lambda: _env_float("ZT_RAG_MIN_SCORE", 0.08))
    embedder: str = field(default_factory=lambda: _env("ZT_RAG_EMBEDDER", "hashing"))
    embed_dim: int = field(default_factory=lambda: _env_int("ZT_RAG_EMBED_DIM", 384))
    rrf_k: int = 60


@dataclass
class ValidatorConfig:
    cos_accept: float = field(default_factory=lambda: _env_float("ZT_VALIDATOR_COS_ACCEPT", 0.85))
    cos_reject: float = field(default_factory=lambda: _env_float("ZT_VALIDATOR_COS_REJECT", 0.60))
    nli_threshold: float = field(default_factory=lambda: _env_float("ZT_VALIDATOR_NLI_ENTAIL", 0.5))
    nli_model: str = field(
        default_factory=lambda: _env("ZT_VALIDATOR_NLI_MODEL",
                                     "cross-encoder/deberta-v3-base-mnli"))


@dataclass
class LlmConfig:
    gateway_url: str = field(default_factory=lambda: _env("ZT_RAG_GATEWAY", ""))
    local_url: str = field(default_factory=lambda: _env("ZT_RAG_LOCAL_LLM", ""))
    timeout_secs: float = field(default_factory=lambda: _env_float("ZT_RAG_LLM_TIMEOUT", 15.0))
    mode: str = field(default_factory=lambda: _env("ZT_RAG_LLM_MODE", "extractive"))
    # extractive — детерминированный офлайн-генератор (dev/CI);
    # gateway — через L4 (F-D-02); local — локальный Qwen HTTP-endpoint.


@dataclass
class RagConfig:
    ingestion: IngestionConfig = field(default_factory=IngestionConfig)
    retrieval: RetrievalConfig = field(default_factory=RetrievalConfig)
    validator: ValidatorConfig = field(default_factory=ValidatorConfig)
    llm: LlmConfig = field(default_factory=LlmConfig)
    kb_dir: str = field(default_factory=lambda: _env("ZT_RAG_KB", "/var/rag/kb"))
    audit_socket: str = field(default_factory=lambda: _env("ZT_RAG_AUDIT_SOCKET", ""))
    audit_spool: str = field(
        default_factory=lambda: _env("ZT_RAG_AUDIT_SPOOL", "/var/rag/audit-spool.jsonl"))

    def validate(self) -> List[str]:
        return self.ingestion.validate()
