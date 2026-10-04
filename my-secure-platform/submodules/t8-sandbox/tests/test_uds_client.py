"""Тесты UDS-клиента IPC-шины: валидация sun_path (F-E-04), обмен, SO_PEERCRED."""
from __future__ import annotations

import json
import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "grpc_client"))

from zt_uds_client import (  # noqa: E402
    PeerCredentials,
    UdsValidationError,
    ZtUdsClient,
    check_peer_allowed,
    get_peer_credentials,
    validate_sun_path,
)


@pytest.fixture()
def sock_dir(tmp_path, monkeypatch):
    d = tmp_path / "zt-core"
    d.mkdir()
    return str(d)


# ---------------------------------------------------------------- sun_path
def test_validate_ok(sock_dir):
    p = os.path.join(sock_dir, "rag.sock")
    assert validate_sun_path(p, socket_dir=sock_dir) == os.path.realpath(p)


def test_validate_rejects_relative(sock_dir):
    with pytest.raises(UdsValidationError, match="абсолютным"):
        validate_sun_path("rag.sock", socket_dir=sock_dir)


def test_validate_rejects_abstract_namespace(sock_dir):
    with pytest.raises(UdsValidationError, match="abstract"):
        validate_sun_path("\x00hidden", socket_dir=sock_dir)


def test_validate_rejects_wrong_suffix(sock_dir):
    with pytest.raises(UdsValidationError, match=r"\.sock"):
        validate_sun_path(os.path.join(sock_dir, "rag.socket"), socket_dir=sock_dir)


def test_validate_rejects_traversal(sock_dir):
    with pytest.raises(UdsValidationError, match="traversal"):
        validate_sun_path(os.path.join(sock_dir, "..", "evil.sock"),
                          socket_dir=sock_dir)


def test_validate_rejects_outside_dir(sock_dir):
    with pytest.raises(UdsValidationError, match="вне разрешённого"):
        validate_sun_path("/tmp/evil.sock", socket_dir=sock_dir)


def test_validate_rejects_too_long(sock_dir):
    long_name = "x" * 200
    with pytest.raises(UdsValidationError, match="длиннее"):
        validate_sun_path(os.path.join(sock_dir, long_name + ".sock"),
                          socket_dir=sock_dir)


def test_validate_symlink_escape_blocked(sock_dir, tmp_path):
    """Symlink из каталога шины наружу — realpath уходит за пределы → отказ."""
    outside = tmp_path / "outside"
    outside.mkdir()
    real = outside / "real.sock"
    link = os.path.join(sock_dir, "link.sock")
    os.symlink(real, link)
    with pytest.raises(UdsValidationError, match="вне разрешённого"):
        validate_sun_path(link, socket_dir=sock_dir)


def test_validate_allowlist(sock_dir):
    p = os.path.join(sock_dir, "rag.sock")
    with pytest.raises(UdsValidationError, match="allow-list"):
        validate_sun_path(p, socket_dir=sock_dir,
                          allowed_paths=(os.path.join(sock_dir, "other.sock"),))
    assert validate_sun_path(p, socket_dir=sock_dir, allowed_paths=(p,))


# ------------------------------------------------------------ обмен и peercred
class _EchoServer(threading.Thread):
    """Минимальный JSON-line сервер с SO_PEERCRED-проверкой."""

    def __init__(self, path: str):
        super().__init__(daemon=True)
        self.path = path
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path)
        self.srv.listen(4)
        self.peer: PeerCredentials | None = None
        self.stop_flag = False

    def run(self):
        while not self.stop_flag:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            with conn:
                self.peer = get_peer_credentials(conn)
                buf = b""
                conn.settimeout(2.0)
                try:
                    while b"\n" not in buf:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        buf += chunk
                except socket.timeout:
                    pass
                line, _, _ = buf.partition(b"\n")
                try:
                    req = json.loads(line)
                    resp = {"result": {"echo": req.get("method"),
                                       "peer": self.peer.as_dict()}}
                except json.JSONDecodeError:
                    resp = {"error": "bad json"}
                conn.sendall(json.dumps(resp).encode() + b"\n")

    def close(self):
        self.stop_flag = True
        try:
            self.srv.close()
        except OSError:
            pass
        if os.path.exists(self.path):
            os.unlink(self.path)


@pytest.fixture()
def echo_server(sock_dir):
    path = os.path.join(sock_dir, "rag.sock")
    srv = _EchoServer(path)
    srv.start()
    yield path, srv
    srv.close()
    srv.join(timeout=2)


def test_client_roundtrip(echo_server, sock_dir):
    path, srv = echo_server
    client = ZtUdsClient(path, socket_dir=sock_dir, timeout=3.0)
    client.connect()
    resp = client.call("Query", {"q": "ping"}, request_id="t-1")
    client.close()
    assert resp["result"]["echo"] == "Query"
    peer = resp["result"]["peer"]
    assert peer["pid"] == os.getpid()
    assert peer["uid"] == os.getuid()


def test_server_side_peercred_check(echo_server, sock_dir):
    path, srv = echo_server
    client = ZtUdsClient(path, socket_dir=sock_dir, timeout=3.0)
    client.connect()
    client.call("Health")
    client.close()
    import time
    time.sleep(0.2)
    assert srv.peer is not None
    # check_peer_allowed: наш uid разрешён, чужой — нет
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.connect(path)
    cred = get_peer_credentials(conn)
    check_peer_allowed(conn, allowed_uids=(cred.uid,))
    with pytest.raises(ConnectionError, match="allow-list"):
        check_peer_allowed(conn, allowed_uids=(cred.uid + 12345,))
    conn.close()


def test_client_connect_retry_on_absent(sock_dir):
    client = ZtUdsClient(os.path.join(sock_dir, "absent.sock"),
                         socket_dir=sock_dir, timeout=0.5)
    with pytest.raises(ConnectionError):
        client.connect(retries=1, retry_delay=0.05)


def test_client_call_without_connect(sock_dir):
    client = ZtUdsClient(os.path.join(sock_dir, "rag.sock"), socket_dir=sock_dir)
    with pytest.raises(ConnectionError, match="not connected"):
        client.call("Query")
