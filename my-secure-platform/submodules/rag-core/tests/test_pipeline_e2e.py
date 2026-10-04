"""E2E-тесты пайплайна RAG: query-цикл, AC-06, аудит, персистентность, сервер."""
from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

import pytest

from rag_core.config import RagConfig
from rag_core.pipeline import RagPipeline
from rag_core.prompts.isolation import FALLBACK_ANSWER
from rag_core.server import RagServer, validate_socket_path, PeerRejectedError


# ---------------------------------------------------------------- query cycle

def test_query_answered_from_kb(filled_pipeline: RagPipeline):
    answer = filled_pipeline.query("Какая планета является третьей от Солнца?")
    assert not answer.is_fallback or answer.answer == FALLBACK_ANSWER
    if not answer.is_fallback:
        assert "земля" in answer.answer.lower() or "третья" in answer.answer.lower()
    assert answer.context_chunks, "контекст должен прилагаться для форензики"
    assert len(answer.answer_hash) == 64


def test_ac06_out_of_kb_questions_all_fallback(filled_pipeline: RagPipeline):
    """AC-06: 100 вопросов вне базы → 100% fallback (детерминированно)."""
    questions = [
        "Какой рецепт борща у моей бабушки?",
        "Сколько весит слон в Африке в 2031 году?",
        "Назови лучший курс акций Tesla вчера",
        "Какая погода сейчас на Марсианской базе-2?",
        "Перечисли все транзакции блокчейна Zcash за март",
        "Кто выиграл чемпионат мира по квиддичу?",
        "Какой IP-адрес у роутера в офисе на Ленина 5?",
        "Сколько атомов в чашке кофе на столе справа?",
        "Расшифруй этот hash 9f86d081884c7d65",
        "Что сказал директор на вчерашнем совещании?",
    ]
    fallbacks = 0
    for i in range(100):
        q = questions[i % len(questions)] + f" (вариант {i})"
        answer = filled_pipeline.query(q)
        if answer.is_fallback and answer.answer == FALLBACK_ANSWER:
            fallbacks += 1
    assert fallbacks == 100, f"AC-06 нарушен: fallback {fallbacks}/100"


def test_query_audited_to_spool(config: RagConfig, filled_pipeline: RagPipeline):
    filled_pipeline.query("Какая планета красная?")
    spool = Path(config.audit_spool)
    assert spool.exists(), "аудит-спул обязан создаваться при недоступной шине"
    events = [json.loads(l) for l in spool.read_text().splitlines() if l.strip()]
    kinds = {e["kind"] for e in events}
    assert "RECORD_KIND_PROMPT" in kinds, "промпт обязан писаться в WORM (NF-09)"
    assert "RECORD_KIND_VALIDATOR_VERDICT" in kinds, "вердикт+хэш — в WORM (F-D-03 п.4)"


def test_ingest_audited(filled_pipeline: RagPipeline, config: RagConfig):
    spool = Path(config.audit_spool)
    events = [json.loads(l) for l in spool.read_text().splitlines() if l.strip()]
    ingest_events = [e for e in events if e["kind"] == "RECORD_KIND_INTEGRITY"]
    assert ingest_events, "ingest обязан писаться в аудит"


# ---------------------------------------------------------------- persistence

def test_kb_save_load_roundtrip(filled_pipeline: RagPipeline, tmp_path):
    target = tmp_path / "kb-export"
    filled_pipeline.save_kb(str(target))
    assert (target / "chunks.json").exists()

    cfg2 = RagConfig()
    cfg2.kb_dir = str(target)
    cfg2.audit_socket = ""
    cfg2.audit_spool = str(tmp_path / "spool2.jsonl")
    cfg2.retrieval.min_score = 0.02
    fresh = RagPipeline(cfg2)
    loaded = fresh.load_kb(str(target))
    assert loaded == len(filled_pipeline.store.all_chunks())
    scored = fresh.retrieve("красная планета")
    assert scored and "марс" in scored[0].chunk.text.lower()


# ---------------------------------------------------------------- server

def test_socket_path_validation(tmp_path):
    ok = tmp_path / "zt-core"
    ok.mkdir()
    validate_socket_path(str(ok / "rag.sock"), socket_dir=str(ok))
    with pytest.raises(PeerRejectedError):
        validate_socket_path("/tmp/evil.sock", socket_dir=str(ok))
    with pytest.raises(PeerRejectedError):
        validate_socket_path(str(ok / "rag.socket"), socket_dir=str(ok))


class _Client:
    def __init__(self, path: str):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5.0)
        self.sock.connect(path)

    def call(self, method: str, params: dict) -> dict:
        req = {"jsonrpc": "zt-uds/1.0", "method": method, "params": params,
               "id": time.time_ns()}
        self.sock.sendall(json.dumps(req, ensure_ascii=False).encode() + b"\n")
        buf = b""
        while b"\n" not in buf:
            chunk = self.sock.recv(65536)
            assert chunk, "connection closed"
            buf += chunk
        return json.loads(buf.split(b"\n", 1)[0])

    def close(self):
        self.sock.close()


@pytest.fixture()
def server(filled_pipeline: RagPipeline, tmp_path):
    sock_dir = tmp_path / "zt-core"
    sock_dir.mkdir()
    path = str(sock_dir / "rag.sock")
    import os
    srv = RagServer(filled_pipeline, allowed_uids=(os.getuid(),))
    thread = threading.Thread(target=srv.serve, args=(path,), daemon=True)
    thread.start()
    for _ in range(100):
        if os.path.exists(path):
            break
        time.sleep(0.02)
    yield path, srv
    srv.stop()
    thread.join(timeout=2)


def test_server_roundtrip_ingest_query(server):
    path, _ = server
    client = _Client(path)
    try:
        resp = client.call("Health", {})
        assert resp["result"]["healthy"] is True
        assert resp["result"]["kb_chunks"] > 0

        resp = client.call("Ingest", {"documents": [{
            "doc_id": "doc-worm",
            "content": "WORM-журнал append-only с BLAKE3 hash-chain и Ed25519 "
                       "чекпоинтами защищает аудит от усечения и подмены.",
            "source_uri": "kb://worm.txt",
        }]})
        assert resp["result"]["accepted"] == 1

        resp = client.call("Query", {"question": "Какая планета третья от Солнца?",
                                      "query_id": "q-test-1"})
        result = resp["result"]
        assert result["query_id"] == "q-test-1"
        assert len(result["answer_hash"]) == 64

        resp = client.call("Retrieve", {"question": "BLAKE3 hash-chain", "top_k": 3})
        chunks = resp["result"]["chunks"]
        assert chunks and chunks[0]["final_rank"] == 1

        resp = client.call("ValidateAnswer", {
            "answer": "Земля — третья планета от Солнца.",
            "context": ["Земля — третья планета от Солнца, единственная с жизнью."],
        })
        assert resp["result"]["decided_by"] in ("RULE_BASED", "EMBEDDING_SIMILARITY", "NLI")

        resp = client.call("GetKbStats", {})
        assert resp["result"]["chunks"] > 0
        assert resp["result"]["dedup_skipped"] >= 0
    finally:
        client.close()


def test_server_unknown_method_error(server):
    path, _ = server
    client = _Client(path)
    try:
        resp = client.call("NoSuchMethod", {})
        assert "error" in resp and "unknown method" in resp["error"]
    finally:
        client.close()


# ---------------------------------------------------------------- warmup

def test_warmup_all_marks_ready():
    from rag_core import models
    report = models.warmup_all()
    assert report["embedder"] >= 0
    assert models.is_warmed_up()
    assert "embedder" in models.loaded_models()
