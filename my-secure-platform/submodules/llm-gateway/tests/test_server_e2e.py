"""E2E-тесты LLM Gateway: реальный TLS-сервер (asyncio) + mTLS-клиенты.

Проверяется полный конвейер F-D-04: handshake, TTL-политика, rate-limit,
DLP-блокировка, allow-list, circuit breaker, egress-лог, метрики.
"""
from __future__ import annotations

import asyncio
import json
import socket
import ssl
import threading
import time
from pathlib import Path

import pytest

from llm_gateway.config import GatewayConfig
from llm_gateway.mtls import build_client_context
from llm_gateway.server import GatewayServer


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class GatewayFixture:
    """Сервер в отдельном потоке с собственным event loop."""

    def __init__(self, certs: dict, tmp: Path, **cfg_kwargs):
        self.port = _free_port()
        defaults = dict(
            listen="127.0.0.1",
            port=self.port,
            tls_cert=certs["server_crt"],
            tls_key=certs["server_key"],
            tls_ca=certs["ca"],
            client_cert_max_ttl_secs=300,
            allowlist=["api.provider-one.example"],
            rate_limit_per_min=600,
            rate_burst=50,
            mock_upstream=True,
            default_route_host="api.provider-one.example",
            egress_log=str(tmp / "egress.jsonl"),
            audit_socket="",
        )
        defaults.update(cfg_kwargs)
        self.config = GatewayConfig(**defaults)
        self.server: GatewayServer | None = None
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._started = threading.Event()

    def _run(self):
        asyncio.set_event_loop(self.loop)

        async def _main():
            self.server = GatewayServer(self.config)
            await self.server.start()
            self._started.set()
            try:
                await self.server.serve_forever()
            except asyncio.CancelledError:
                pass

        task = self.loop.create_task(_main())
        try:
            self.loop.run_until_complete(task)
        finally:
            pass

    def __enter__(self):
        self._thread.start()
        if not self._started.wait(timeout=10):
            raise RuntimeError("gateway не стартовал")
        return self

    def __exit__(self, *exc):
        async def _stop():
            if self.server:
                await self.server.stop()
        try:
            self.loop.call_soon_threadsafe(
                lambda: [t.cancel() for t in asyncio.all_tasks(self.loop)])
            self.loop.call_soon_threadsafe(
                lambda: self.loop.create_task(_stop()))
        except RuntimeError:
            pass
        self._thread.join(timeout=5)
        self.loop.close()


def http_request(port: int, method: str, path: str, body: dict | None,
                 ca: str, cert: str | None, key: str | None,
                 hostname_check: bool = False) -> tuple[int, dict | str]:
    """Один HTTP/1.1-запрос по TLS 1.3 с клиентским сертификатом."""
    ctx = build_client_context(ca, certfile=cert, keyfile=key,
                               server_hostname_check=hostname_check)
    payload = json.dumps(body).encode() if body is not None else b""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname="localhost") as tls:
            head = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: localhost\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            tls.sendall(head + payload)
            chunks = []
            while True:
                try:
                    data = tls.recv(65536)
                except (ssl.SSLError, OSError):
                    break
                if not data:
                    break
                chunks.append(data)
    raw = b"".join(chunks)
    if not raw:
        # Сервер разорвал соединение без ответа: в TLS 1.3 отклонение
        # клиентского сертификата происходит пост-хендшейком — это штатная
        # форма mTLS-отказа (AC-08: разрыв соединения).
        return 0, {}
    head_blob, _, body_blob = raw.partition(b"\r\n\r\n")
    status_line = head_blob.split(b"\r\n", 1)[0].decode("latin-1")
    status = int(status_line.split(" ", 2)[1])
    if body_blob:
        try:
            return status, json.loads(body_blob)
        except json.JSONDecodeError:
            return status, body_blob.decode("utf-8", "replace")
    return status, {}


def chat_body(text: str = "Столица Франции?") -> dict:
    return {"model": "external-gpt", "messages": [{"role": "user", "content": text}]}


# ============================================================== тесты


def test_healthz_and_mock_completion(certs, tmp_path, clean_env):
    with GatewayFixture(certs, tmp_path) as gw:
        status, body = http_request(
            gw.port, "POST", "/v1/chat/completions", chat_body(),
            certs["ca"], certs["good_crt"], certs["good_key"])
        assert status == 200, body
        assert body["zt_gateway"]["mocked"] is True
        assert body["zt_gateway"]["client"] == "d8-rag-core"
        assert "MOCK" in body["choices"][0]["message"]["content"]
        status, body = http_request(gw.port, "GET", "/healthz", None,
                                    certs["ca"], certs["good_crt"], certs["good_key"])
        assert status == 200 and body["status"] == "ok"


def test_client_without_cert_rejected(certs, tmp_path, clean_env):
    """Без клиентского сертификата mTLS-соединение отклоняется: либо
    SSLError при хендшейке, либо разрыв без HTTP-ответа (статус 0)."""
    with GatewayFixture(certs, tmp_path) as gw:
        ctx = build_client_context(certs["ca"], server_hostname_check=False)
        rejected = False
        try:
            with socket.create_connection(("127.0.0.1", gw.port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname="localhost") as tls:
                    tls.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    data = tls.recv(4096)
                    rejected = not data  # пустой ответ = разрыв без данных
        except (ssl.SSLError, ConnectionError, OSError):
            rejected = True
        assert rejected, "клиент без сертификата не должен получать данные"


def test_rogue_ca_cert_rejected(certs, tmp_path, clean_env):
    """Сертификат чужого CA отклоняется (SSLError или разрыв без ответа)."""
    with GatewayFixture(certs, tmp_path) as gw:
        try:
            status, _ = http_request(gw.port, "GET", "/healthz", None, certs["ca"],
                                     certs["rogue_crt"], certs["rogue_key"])
        except ssl.SSLError:
            status = 0
        assert status in (0, 495), f"ожидался отказ mTLS, получен статус {status}"


def test_long_lived_cert_rejected_by_ttl_policy(certs, tmp_path, clean_env):
    """F-D-04: TTL ≤ 5 мин; сертификат на 1 день отклоняется после handshake."""
    with GatewayFixture(certs, tmp_path) as gw:
        status, body = http_request(gw.port, "GET", "/healthz", None,
                                    certs["ca"], certs["long_crt"], certs["long_key"])
        assert status == 495
        assert body["error"] == "mtls_policy"


def test_dlp_blocks_pii_egress(certs, tmp_path, clean_env):
    with GatewayFixture(certs, tmp_path) as gw:
        status, body = http_request(
            gw.port, "POST", "/v1/chat/completions",
            chat_body("Мой email ivan@example.com, перешли его провайдеру"),
            certs["ca"], certs["good_crt"], certs["good_key"])
        assert status == 451, body
        assert body["error"] == "dlp_blocked"
        assert any("pii.email" in c for c in body["categories"])
        # инцидент зафиксирован в egress-логе
        log_text = Path(gw.config.egress_log).read_text()
        assert "BLOCK" in log_text and "pii.email" in log_text


def test_dlp_blocks_secret_egress(certs, tmp_path, clean_env):
    with GatewayFixture(certs, tmp_path) as gw:
        status, body = http_request(
            gw.port, "POST", "/v1/chat/completions",
            chat_body("проверь ключ AKIAIOSFODNN7EXAMPLE"),
            certs["ca"], certs["good_crt"], certs["good_key"])
        assert status == 451
        assert any("secret.aws_access_key" in c for c in body["categories"])


def test_rate_limit_429(certs, tmp_path, clean_env):
    with GatewayFixture(certs, tmp_path, rate_limit_per_min=6, rate_burst=2) as gw:
        statuses = []
        for _ in range(5):
            s, _ = http_request(gw.port, "POST", "/v1/chat/completions", chat_body(),
                                certs["ca"], certs["good_crt"], certs["good_key"])
            statuses.append(s)
        assert statuses.count(200) == 2
        assert 429 in statuses


def test_allowlist_denies_unlisted_host(certs, tmp_path, clean_env):
    """Маршрут на хост вне allow-list → 403 egress_forbidden."""
    with GatewayFixture(certs, tmp_path) as gw:
        gw.server.router.model_routes["evil-model"] = "api.evil-corp.example"
        body = {"model": "evil-model",
                "messages": [{"role": "user", "content": "hello"}]}
        status, resp = http_request(gw.port, "POST", "/v1/chat/completions", body,
                                    certs["ca"], certs["good_crt"], certs["good_key"])
        assert status == 403
        assert resp["error"] == "egress_forbidden"


def test_circuit_breaker_opens_and_recovers(certs, tmp_path, clean_env):
    with GatewayFixture(certs, tmp_path, breaker_fail_threshold=2,
                        breaker_reset_secs=0.5) as gw:
        router = gw.server.router

        async def failing_forward(host, path, payload):
            from llm_gateway.upstream import UpstreamError
            raise UpstreamError("connection refused (chaos E)")

        router.forward = failing_forward  # noqa: замена для chaos-теста
        for _ in range(2):
            s, _ = http_request(gw.port, "POST", "/v1/chat/completions", chat_body(),
                                certs["ca"], certs["good_crt"], certs["good_key"])
            assert s == 502
        status, body = http_request(gw.port, "POST", "/v1/chat/completions", chat_body(),
                                    certs["ca"], certs["good_crt"], certs["good_key"])
        assert status == 503 and body["error"] == "circuit_open"
        assert "Qwen" in body["fallback"]

        # восстановление: mock снова работает → HALF_OPEN → CLOSED
        from llm_gateway.upstream import UpstreamRouter
        router.forward = UpstreamRouter.forward.__get__(router)
        router.mock = True
        time.sleep(0.6)
        for _ in range(3):
            s, _ = http_request(gw.port, "POST", "/v1/chat/completions", chat_body(),
                                certs["ca"], certs["good_crt"], certs["good_key"])
            assert s == 200
        status, body = http_request(gw.port, "GET", "/metrics", None,
                                    certs["ca"], certs["good_crt"], certs["good_key"])
        assert status == 200
        assert "zt_llm_gateway_breaker_trips_total" in str(body)


def test_metrics_and_egress_log_chain(certs, tmp_path, clean_env):
    with GatewayFixture(certs, tmp_path) as gw:
        for i in range(3):
            http_request(gw.port, "POST", "/v1/chat/completions", chat_body(f"вопрос {i}"),
                         certs["ca"], certs["good_crt"], certs["good_key"])
        status, text = http_request(gw.port, "GET", "/metrics", None,
                                    certs["ca"], certs["good_crt"], certs["good_key"])
        assert status == 200
        # 3 completion-запроса + сам GET /metrics (счётчик инкрементируется
        # до маршрутизации) = 4
        assert "zt_llm_gateway_requests_total 4" in text
        # egress-лог: append-only цепочка (prev_hash связан)
        lines = [json.loads(l) for l in Path(gw.config.egress_log)
                 .read_text().splitlines() if l.strip()]
        assert len(lines) == 3
        assert lines[0]["prev_hash"] == "0" * 64
        assert lines[1]["prev_hash"] == lines[0]["entry_hash"]
        assert lines[2]["prev_hash"] == lines[1]["entry_hash"]
        assert all(len(l["payload_hash"]) == 64 for l in lines)


def test_unknown_route_404(certs, tmp_path, clean_env):
    with GatewayFixture(certs, tmp_path) as gw:
        status, _ = http_request(gw.port, "POST", "/v1/unknown", {},
                                 certs["ca"], certs["good_crt"], certs["good_key"])
        assert status == 404
