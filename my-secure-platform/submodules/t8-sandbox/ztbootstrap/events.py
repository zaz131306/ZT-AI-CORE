"""Спул bootstrap-событий для WORM-аудита (NF-09: 100% логирование).

События Bootstrap Sequence пишутся в append-only JSONL-спул
(``ZT_AUDIT_SPOOL`` / manifest.audit_spool). После старта основной шины
спул вычитывается worm-audit и включается в BLAKE3-цепочку; если шина
недоступна — спул остаётся на диске для последующего ingestion
(runbook §5 «Восстановление WORM после сбоя»).

Формат записи — соответствие audit.proto (поля AppendRequest/AuditRecord):
  {"ts_ns": int, "kind": "RECORD_KIND_BOOTSTRAP"|"RECORD_KIND_INTEGRITY",
   "source": "t8-sandbox/bootstrap", "subject": "d8",
   "payload": {...}}
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

KIND_BOOTSTRAP = "RECORD_KIND_BOOTSTRAP"
KIND_INTEGRITY = "RECORD_KIND_INTEGRITY"
KIND_SECCOMP_VIOLATION = "RECORD_KIND_SECCOMP_VIOLATION"

SOURCE = "t8-sandbox/bootstrap"


@dataclass
class EventSpool:
    """Append-only JSONL-спул событий (деградация безопасна: ошибки записи
    логируются в stderr, но НЕ прерывают bootstrap — аудит дополняется
    через шину после старта)."""

    path: str = ""
    enabled: bool = True
    sync: bool = True   # fsync после записи; MUST быть выключен после применения
                        # SECCOMP-фильтра строгого профиля (fsync не входит в
                        # whitelist Приложения В; доставка в WORM — через UDS-шину)
    _fh: Any = field(default=None, repr=False)

    def open(self) -> None:
        if not self.enabled or not self.path:
            return
        try:
            p = Path(self.path)
            p.parent.mkdir(parents=True, exist_ok=True)
            # append-only: файл открывается только на допись
            self._fh = open(p, "a", encoding="utf-8")
        except OSError as exc:
            self._warn(f"cannot open spool {self.path}: {exc}")
            self._fh = None

    def emit(self, kind: str, payload: dict[str, Any],
             subject: str = "d8") -> None:
        if not self.enabled or self._fh is None:
            return
        record = {
            "ts_ns": time.time_ns(),
            "kind": kind,
            "source": SOURCE,
            "subject": subject,
            "payload": payload,
        }
        try:
            self._fh.write(json.dumps(record, ensure_ascii=False,
                                      separators=(",", ":")) + "\n")
            self._fh.flush()
            if self.sync:
                os.fsync(self._fh.fileno())
        except (OSError, ValueError) as exc:
            self._warn(f"spool write failed: {exc}")

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None

    @staticmethod
    def _warn(msg: str) -> None:
        print(f"[ztbootstrap.events] WARN: {msg}", file=__import__("sys").stderr,
              flush=True)

    def __enter__(self) -> "EventSpool":
        self.open()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()
