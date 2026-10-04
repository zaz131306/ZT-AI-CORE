"""Собственный WORM-лог egress-запросов гейтвея (F-D-04).

Append-only JSONL с хэш-цепочкой (BLAKE3 при наличии пакета `blake3`,
иначе hashlib.blake2b — каноническая цепочка всё равно ведётся
worm-audit (L7) на BLAKE3; локальный лог — зеркало для форензики).

Поле-состав: ts_ns, method, host, model, client_cn, payload_hash,
verdict (PASS/BLOCK + reasons), status, latency_ms, prev_hash.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

try:  # pragma: no cover - зависит от окружения
    import blake3 as _blake3

    def _hash(data: bytes) -> str:
        return _blake3.blake3(data).hexdigest()
    HASH_ALGO = "blake3"
except ImportError:  # pragma: no cover
    def _hash(data: bytes) -> str:
        return "blake2b:" + hashlib.blake2b(data, digest_size=32).hexdigest()
    HASH_ALGO = "blake2b(fallback)"


GENESIS = "0" * 64


class EgressLog:
    """Потокобезопасный append-only журнал egress-событий."""

    def __init__(self, path: str | os.PathLike[str], fsync: bool = True):
        self.path = Path(path)
        self.fsync = fsync
        self._lock = threading.Lock()
        self._head = self._recover_head()
        self._fh: Optional[Any] = None

    def _recover_head(self) -> str:
        if not self.path.exists():
            return GENESIS
        head = GENESIS
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        head = json.loads(line).get("prev_next", head)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return GENESIS
        return head

    def _open(self) -> Any:
        if self._fh is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self.path, "a", encoding="utf-8")
        return self._fh

    def record(self, *, method: str, host: str, model: str, client_cn: str,
               payload: bytes, verdict: str, reasons: list[str],
               status: int, latency_ms: float) -> Dict[str, Any]:
        payload_hash = _hash(payload)
        with self._lock:
            ts = time.time_ns()
            chain_input = f"{self._head}|{payload_hash}|{ts}".encode("utf-8")
            next_hash = _hash(chain_input)
            entry = {
                "ts_ns": ts,
                "method": method,
                "host": host,
                "model": model,
                "client_cn": client_cn,
                "payload_hash": payload_hash,
                "verdict": verdict,
                "reasons": reasons,
                "status": status,
                "latency_ms": round(latency_ms, 3),
                "prev_hash": self._head,
                "entry_hash": next_hash,
                "prev_next": next_hash,
            }
            fh = self._open()
            assert fh is not None
            fh.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
            fh.flush()
            if self.fsync:
                os.fsync(fh.fileno())
            self._head = next_hash
            return entry

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None
