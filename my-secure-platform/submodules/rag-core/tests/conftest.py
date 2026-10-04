"""Общий conftest rag-core: пути и фикстуры KB."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rag_core.config import RagConfig  # noqa: E402
from rag_core.pipeline import RagPipeline  # noqa: E402

KB_DOC_SOLAR = """Солнечная система состоит из Солнца и обращающихся вокруг него объектов.
Восемь планет: Меркурий, Венера, Земля, Марс, Юпитер, Сатурн, Уран и Нептун.
Земля — третья планета от Солнца, единственный известный объект, обладающий жизнью.
Марс — четвёртая планета, его часто называют красной планетой из-за оксида железа на поверхности.
Юпитер — крупнейшая планета системы, его масса превышает суммарную массу всех остальных планет.
"""

KB_DOC_TPM = """TPM 2.0 — аппаратный модуль доверия, хранящий криптографические ключи.
PCR регистры TPM хранят хэши измерений загрузки и рантайма, расширяются операцией extend.
NV-память TPM позволяет хранить монотонные счётчики, используемые для защиты от отката.
Remote Attestation — процедура подтверждения целостности платформы через подпись PCR-значений ключом AK.
"""


@pytest.fixture()
def config(tmp_path) -> RagConfig:
    cfg = RagConfig()
    cfg.kb_dir = str(tmp_path / "kb")
    cfg.audit_socket = ""
    cfg.audit_spool = str(tmp_path / "spool.jsonl")
    # пороги тестов: min_score ниже, чтобы retrieval был детерминирован
    cfg.retrieval.min_score = 0.02
    return cfg


@pytest.fixture()
def pipeline(config: RagConfig) -> RagPipeline:
    return RagPipeline(config)


@pytest.fixture()
def filled_pipeline(pipeline: RagPipeline) -> RagPipeline:
    pipeline.ingest_text("doc-solar", KB_DOC_SOLAR, source_uri="kb://solar.txt")
    pipeline.ingest_text("doc-tpm", KB_DOC_TPM, source_uri="kb://tpm.txt")
    return pipeline
