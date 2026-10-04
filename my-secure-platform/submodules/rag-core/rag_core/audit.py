"""Аудит-хук RAG-ядра: публикация промптов/ответов/вердиктов в WORM (L7).

NF-09: 100% действий ИИ. Транспорт — AF_UNIX /run/zt-core/audit.sock
(audit.proto:Append, line-JSON dev-контур). При недоступности шины —
append-only спул на диске D8 (/var/rag — единственная rw-область),
который worm-audit забирает через IngestSpool после восстановления.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional


class AuditHook:
    def __init__(self, socket_path: str = "", spool_path: str = "",
                 timeout: float = 2.0):
        self.socket_path = socket_path
        self.spool_path = Path(spool_path) if spool_path else None
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self.published = 0
        self.spooled = 0

    def _connect(self) -> Optional[socket.socket]:
        with self._lock:
            if self._sock is not None:
                return self._sock
            if not self.socket_path:
                return None
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                self._sock = sock
                return sock
            except OSError:
                self._sock = None
                return None

    def record(self, kind: str, payload: Dict[str, Any],
               subject: str = "d8", source: str = "rag-core") -> bool:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        sock = self._connect()
        if sock is not None:
            request = {
                "jsonrpc": "zt-uds/1.0",
                "method": "Append",
                "params": {
                    "payload_b64": base64.b64encode(raw).decode("ascii"),
                    "kind": kind, "source": source, "subject": subject,
                },
                "id": time.time_ns(),
            }
            try:
                with self._lock:
                    assert self._sock is not None
                    self._sock.sendall(
                        json.dumps(request, separators=(",", ":")).encode() + b"\n")
                    buf = b""
                    while b"\n" not in buf:
                        chunk = self._sock.recv(65536)
                        if not chunk:
                            raise ConnectionError("audit closed")
                        buf += chunk
                if b'"error"' not in buf:
                    self.published += 1
                    return True
            except (OSError, ValueError, ConnectionError):
                with self._lock:
                    if self._sock is not None:
                        try:
                            self._sock.close()
                        finally:
                            self._sock = None
        # Спул (F: /var/rag — rw-область D8)
        if self.spool_path is not None:
            try:
                self.spool_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.spool_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({
                        "ts_ns": time.time_ns(), "kind": kind, "source": source,
                        "subject": subject, "payload": payload,
                    }, ensure_ascii=False, separators=(",", ":")) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                self.spooled += 1
                return True
            except OSError:
                return False
        return False

    def close(self) -> None:
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                finally:
                    self._sock = None
