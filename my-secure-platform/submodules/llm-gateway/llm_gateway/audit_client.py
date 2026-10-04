"""Клиент WORM-шины (audit.proto:Append) — best-effort публикация egress-
событий гейтвея в worm-audit (L7). Отказ шины НЕ блокирует egress:
событие фиксируется в локальном EgressLog (F-D-04), доставка в L7
повторяется при восстановлении (runbook §5).
"""
from __future__ import annotations

import base64
import json
import socket
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional


class AuditBusClient:
    def __init__(self, socket_path: str, timeout: float = 2.0,
                 spool_path: Optional[str] = None):
        self.socket_path = socket_path
        self.timeout = timeout
        self.spool_path = Path(spool_path) if spool_path else None
        self._lock = threading.Lock()
        self._sock: Optional[socket.socket] = None
        self._published = 0
        self._spooled = 0

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
                return None

    def append(self, *, kind: str, payload: bytes, source: str = "llm-gateway",
               subject: str = "") -> bool:
        """Опубликовать запись; при недоступности шины — в локальный спул."""
        sock = self._connect()
        if sock is not None:
            request = {
                "jsonrpc": "zt-uds/1.0",
                "method": "Append",
                "params": {
                    "payload_b64": base64.b64encode(payload).decode("ascii"),
                    "kind": kind,
                    "source": source,
                    "subject": subject,
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
                            raise ConnectionError("audit bus closed")
                        buf += chunk
                resp = json.loads(buf.split(b"\n", 1)[0])
                if "result" in resp:
                    self._published += 1
                    return True
            except (OSError, ValueError, ConnectionError):
                with self._lock:
                    if self._sock is not None:
                        try:
                            self._sock.close()
                        finally:
                            self._sock = None
        # шина недоступна → спул (доставка позже)
        if self.spool_path is not None:
            try:
                self.spool_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.spool_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({
                        "ts_ns": time.time_ns(),
                        "kind": kind,
                        "source": source,
                        "subject": subject,
                        "payload": {"b64": base64.b64encode(payload).decode("ascii")},
                    }, ensure_ascii=False, separators=(",", ":")) + "\n")
                self._spooled += 1
            except OSError:
                return False
        return False

    def stats(self) -> Dict[str, Any]:
        return {"published": self._published, "spooled": self._spooled,
                "connected": self._sock is not None}

    def close(self) -> None:
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                finally:
                    self._sock = None
