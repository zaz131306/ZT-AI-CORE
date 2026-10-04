"""ZT-AI-CORE UDS-клиент IPC-шины (F-E-04).

Клиентская сторона gRPC-границы D8: соединения ТОЛЬКО по Unix Domain Sockets
в каталог /run/zt-core/ (валидация sun_path до connect). Протокол dev-контура —
line-oriented JSON поверх UDS (контракты полей: api/proto/*.proto); в prod
заменяется на grpc over UDS без изменения валидации пути и peer-проверок.

Серверная сторона обязана проверять SO_PEERCRED — вспомогательная функция
``get_peer_credentials()`` предоставлена здесь же для переиспользования.
"""
from __future__ import annotations

import ctypes
import json
import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Any

DEFAULT_SOCKET_DIR = "/run/zt-core"
ALLOWED_SOCKET_SUFFIX = ".sock"
# sun_path в struct sockaddr_un — 108 байт (включая завершающий NUL).
SUN_PATH_MAX = 108


class UdsValidationError(ValueError):
    """sun_path не прошёл валидацию allow-list (F-E-04)."""


class UdsConnectionError(ConnectionError):
    """Ошибка соединения/обмена по UDS."""


@dataclass(frozen=True)
class PeerCredentials:
    """struct ucred { pid_t pid; uid_t uid; gid_t gid; } (SO_PEERCRED)."""

    pid: int
    uid: int
    gid: int

    def as_dict(self) -> dict[str, int]:
        return {"pid": self.pid, "uid": self.uid, "gid": self.gid}


def validate_sun_path(path: str,
                      socket_dir: str = DEFAULT_SOCKET_DIR,
                      allowed_paths: tuple[str, ...] | None = None) -> str:
    """Валидация sun_path по политике F-E-04.

    Правила:
      * абсолютный путь (abstract-namespace ``\\0...`` запрещён);
      * realpath находится внутри ``socket_dir`` (без symlink-побега);
      * оканчивается на ``.sock``;
      * длина <= 107 байт (лимит sockaddr_un.sun_path);
      * при заданном ``allowed_paths`` — точное вхождение в список.

    :returns: нормализованный путь.
    :raises UdsValidationError: при любом нарушении.
    """
    if not isinstance(path, str) or not path:
        raise UdsValidationError("sun_path пуст или не строка")
    if path.startswith("\x00"):
        raise UdsValidationError("abstract-namespace сокеты запрещены (F-E-04)")
    if not path.startswith("/"):
        raise UdsValidationError(f"sun_path обязан быть абсолютным: {path!r}")
    encoded_len = len(path.encode("utf-8"))
    if encoded_len > SUN_PATH_MAX - 1:
        raise UdsValidationError(
            f"sun_path длиннее {SUN_PATH_MAX - 1} байт: {encoded_len}")
    if ".." in path.split("/"):
        raise UdsValidationError(f"traversal в sun_path запрещён: {path!r}")
    if not path.endswith(ALLOWED_SOCKET_SUFFIX):
        raise UdsValidationError(
            f"sun_path обязан оканчиваться на {ALLOWED_SOCKET_SUFFIX!r}: {path!r}")

    socket_dir = os.path.realpath(socket_dir)
    real = os.path.realpath(path)
    if not (real == socket_dir or real.startswith(socket_dir + os.sep)):
        raise UdsValidationError(
            f"sun_path вне разрешённого каталога {socket_dir}: {path!r} -> {real}")

    if allowed_paths is not None:
        allowed_real = {os.path.realpath(p) for p in allowed_paths}
        if real not in allowed_real:
            raise UdsValidationError(
                f"sun_path не в allow-list: {path!r}")
    return real


def get_peer_credentials(conn: socket.socket) -> PeerCredentials:
    """SO_PEERCRED для принятого UDS-соединения (серверная сторона, F-E-04)."""
    SO_PEERCRED = 17  # include/asm-generic/socket.h
    SOL_SOCKET = 1
    buf = conn.getsockopt(SOL_SOCKET, SO_PEERCRED, struct.calcsize("iii"))
    pid, uid, gid = struct.unpack("iii", buf)
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


def check_peer_allowed(conn: socket.socket,
                       allowed_uids: tuple[int, ...] = (0,),
                       allowed_gids: tuple[int, ...] | None = None,
                       self_pid: int | None = None) -> PeerCredentials:
    """Проверить peer-креденшелы соединения; исключить self-connect.

    :raises UdsConnectionError: uid/gid не в allow-list или соединение с самим собой.
    """
    cred = get_peer_credentials(conn)
    if self_pid is not None and cred.pid == self_pid:
        raise UdsConnectionError(
            f"self-connect запрещён (pid={cred.pid}) — возможная петля IPC")
    if cred.uid not in allowed_uids:
        raise UdsConnectionError(
            f"uid={cred.uid} не в allow-list {allowed_uids}")
    if allowed_gids is not None and cred.gid not in allowed_gids:
        raise UdsConnectionError(
            f"gid={cred.gid} не в allow-list {allowed_gids}")
    return cred


class ZtUdsClient:
    """Клиент IPC-шины ZT-AI-CORE (line-oriented JSON поверх AF_UNIX).

    Пример::

        client = ZtUdsClient("/run/zt-core/audit.sock")
        client.connect()
        resp = client.call("Append", {"kind": "PROMPT", "payload_b64": "..."})
        client.close()
    """

    def __init__(self, sun_path: str,
                 socket_dir: str = DEFAULT_SOCKET_DIR,
                 allowed_paths: tuple[str, ...] | None = None,
                 timeout: float = 5.0):
        self.sun_path = validate_sun_path(sun_path, socket_dir, allowed_paths)
        self.timeout = timeout
        self._sock: socket.socket | None = None

    # -- соединение -------------------------------------------------------------
    def connect(self, retries: int = 0, retry_delay: float = 0.2) -> None:
        last_err: OSError | None = None
        for attempt in range(retries + 1):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect(self.sun_path)
                self._sock = sock
                return
            except OSError as exc:
                last_err = exc
                sock.close()
                if attempt < retries:
                    time.sleep(retry_delay)
        raise UdsConnectionError(
            f"connect({self.sun_path}) failed: {last_err}") from last_err

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self) -> "ZtUdsClient":
        if self._sock is None:
            self.connect()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    # -- обмен -------------------------------------------------------------------
    def call(self, method: str, params: dict[str, Any] | None = None,
             request_id: str | None = None) -> dict[str, Any]:
        """Один RPC: отправить {method, params, id} — получить ответ-dict."""
        if self._sock is None:
            raise UdsConnectionError("not connected")
        payload = {
            "jsonrpc": "zt-uds/1.0",
            "method": method,
            "params": params or {},
            "id": request_id or f"{os.getpid()}-{time.time_ns()}",
        }
        line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if len(line.encode("utf-8")) > 4 * 1024 * 1024:
            raise UdsConnectionError("request too large (>4 MiB)")
        try:
            self._sock.sendall(line.encode("utf-8") + b"\n")
        except OSError as exc:
            raise UdsConnectionError(f"send failed: {exc}") from exc
        response_line = self._recv_line()
        try:
            resp = json.loads(response_line)
        except json.JSONDecodeError as exc:
            raise UdsConnectionError(
                f"invalid JSON response: {response_line[:200]!r}") from exc
        if isinstance(resp, dict) and resp.get("error"):
            raise UdsConnectionError(
                f"server error for {method}: {resp['error']}")
        return resp

    def _recv_line(self, max_bytes: int = 16 * 1024 * 1024) -> str:
        assert self._sock is not None
        chunks: list[bytes] = []
        total = 0
        while True:
            try:
                b = self._sock.recv(65536)
            except socket.timeout as exc:
                raise UdsConnectionError("recv timeout") from exc
            except OSError as exc:
                raise UdsConnectionError(f"recv failed: {exc}") from exc
            if not b:
                raise UdsConnectionError("connection closed by peer")
            chunks.append(b)
            total += len(b)
            if total > max_bytes:
                raise UdsConnectionError("response too large")
            if b"\n" in b:
                raw = b"".join(chunks)
                line, _, _rest = raw.partition(b"\n")
                return line.decode("utf-8")


def peercred_available() -> bool:
    """Доступен ли SO_PEERCRED на данной платформе (Linux)."""
    return hasattr(socket, "AF_UNIX") and os.name == "posix" and \
        struct.calcsize("iii") > 0 and ctypes.sizeof(ctypes.c_int) == 4
