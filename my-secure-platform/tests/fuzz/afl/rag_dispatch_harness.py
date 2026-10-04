#!/usr/bin/env python3
"""AFL++ harness: фаззинг UDS-dispatch rag-core (rag.proto-контракт).

Вход: одна строка JSON на stdin. Инвариант: RagServer.handle возвращает
JSON-ответ с "result" или "error"; любое неперехваченное исключение = crash.

Запуск:
    afl-fuzz -i seeds -o findings -- python3 rag_dispatch_harness.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "submodules" / "rag-core"))

from rag_core.config import RagConfig  # noqa: E402
from rag_core.pipeline import RagPipeline  # noqa: E402
from rag_core.server import RagServer  # noqa: E402

_TMP = tempfile.mkdtemp(prefix="zt-rag-fuzz-")
_cfg = RagConfig()
_cfg.kb_dir = str(Path(_TMP) / "kb")
_cfg.audit_socket = ""
_cfg.audit_spool = str(Path(_TMP) / "spool.jsonl")
_cfg.retrieval.min_score = 0.0
_SERVER = RagServer(RagPipeline(_cfg), allowed_uids=(os.getuid(),))
# минимальное наполнение KB, чтобы Query/Retrieve имели материал
_SERVER.pipeline.ingest_text("fuzz-doc", "Планеты солнечной системы: Меркурий, Венера, Земля, Марс.")


def main() -> int:
    raw = sys.stdin.buffer.read()
    try:
        request = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return 0
    response = _SERVER.handle(request)
    if not isinstance(response, dict):
        sys.stderr.write(f"CRASH: response not dict: {type(response)}\n")
        return 1
    if "result" not in response and "error" not in response:
        sys.stderr.write(f"CRASH: response без result/error: {response!r:.300}\n")
        return 1
    try:
        json.dumps(response, default=str)
    except (TypeError, ValueError, OverflowError) as exc:
        sys.stderr.write(f"CRASH: response не сериализуем: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
