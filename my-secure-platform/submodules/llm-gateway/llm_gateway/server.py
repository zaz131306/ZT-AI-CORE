"""L4 LLM Gateway: asyncio mTLS-сервер с конвейером F-D-04.

Конвейер запроса POST /v1/chat/completions:
  1. mTLS: клиентский сертификат обязателен; TTL ≤ 5 мин (иначе разрыв);
  2. Rate-limit по CN клиента (token bucket, N/мин);
  3. Egress DLP: сканирование ИСХОДЯЩЕГО payload (PII/секреты/фразы) —
     срабатывание → немедленная блокировка (fail fast);
  4. Allow-list доменов провайдера;
  5. Circuit breaker на хост;
  6. Upstream (mock/real);
  7. DLP-скан ответа (defense in depth: блокировка утечки в обе стороны);
  8. Egress WORM-лог (хэш payload + метаданные) + публикация в L7;
  9. Prometheus-метрики.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import signal
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .allowlist import DomainAllowlist, explain_rejection
from .audit_client import AuditBusClient
from .breaker import BreakerRegistry, CircuitOpenError
from .config import GatewayConfig
from .dlp import DlpScanner
from .egress_log import EgressLog
from .mtls import (
    MtlsPolicyError,
    build_server_context,
    enforce_short_lived_ttl,
    subject_common_name,
)
from .ratelimit import TokenBucketLimiter
from .upstream import UpstreamError, UpstreamRouter

log = logging.getLogger("llm-gateway")

SERVER_HEADER = "ZT-AI-CORE-LLM-Gateway/2.4"


@dataclass
class GatewayMetrics:
    requests_total: int = 0
    tls_rejected: int = 0
    ttl_rejected: int = 0
    dlp_blocked: int = 0
    rate_limited: int = 0
    allowlist_denied: int = 0
    breaker_rejected: int = 0
    upstream_errors: int = 0
    upstream_ok: int = 0
    latency_sum_ms: float = 0.0
    extra: Dict[str, Any] = field(default_factory=dict)

    def render_prometheus(self, breakers: Dict[str, Dict[str, object]],
                          ratelimit_stats: Dict[str, int]) -> str:
        lines = [
            "# HELP zt_llm_gateway_requests_total Всего запросов через L4",
            "# TYPE zt_llm_gateway_requests_total counter",
            f"zt_llm_gateway_requests_total {self.requests_total}",
            f"zt_llm_gateway_tls_rejected_total {self.tls_rejected}",
            f"zt_llm_gateway_ttl_rejected_total {self.ttl_rejected}",
            f"zt_llm_gateway_dlp_blocked_total {self.dlp_blocked}",
            f"zt_llm_gateway_rate_limited_total {self.rate_limited}",
            f"zt_llm_gateway_allowlist_denied_total {self.allowlist_denied}",
            f"zt_llm_gateway_breaker_rejected_total {self.breaker_rejected}",
            f"zt_llm_gateway_upstream_errors_total {self.upstream_errors}",
            f"zt_llm_gateway_upstream_ok_total {self.upstream_ok}",
            f"zt_llm_gateway_latency_avg_ms "
            f"{(self.latency_sum_ms / self.requests_total) if self.requests_total else 0:.3f}",
            f"zt_llm_gateway_rate_allowed_total {ratelimit_stats.get('allowed', 0)}",
            f"zt_llm_gateway_rate_denied_total {ratelimit_stats.get('denied', 0)}",
        ]
        for name, snap in breakers.items():
            state_code = {"CLOSED": 0, "HALF_OPEN": 1, "OPEN": 2}.get(
                str(snap.get("state", "CLOSED")), 0)
            lines.append(
                f'zt_llm_gateway_breaker_state{{upstream="{name}"}} {state_code}')
            lines.append(
                f'zt_llm_gateway_breaker_trips_total{{upstream="{name}"}} '
                f'{snap.get("trips", 0)}')
        return "\n".join(lines) + "\n"


class GatewayServer:
    def __init__(self, config: GatewayConfig):
        self.config = config
        problems = config.validate()
        if problems:
            raise ValueError("конфигурация LLM Gateway невалидна: " + "; ".join(problems))
        self.allowlist = DomainAllowlist(config.allowlist)
        self.limiter = TokenBucketLimiter(config.rate_limit_per_min,
                                          burst=config.rate_burst)
        self.breakers = BreakerRegistry(config.breaker_fail_threshold,
                                        config.breaker_reset_secs,
                                        config.breaker_half_open_max)
        self.dlp = DlpScanner(extra_internal_uuids=config.dlp_extra_uuids)
        self.egress_log = EgressLog(config.egress_log)
        self.audit = AuditBusClient(
            config.audit_socket,
            # спул для отложенной доставки в L7 при недоступной шине (runbook §5);
            # без сконфигурированной шины спул не ведётся
            spool_path=(config.egress_log + ".audit-spool") if config.audit_socket else None)
        self.router = UpstreamRouter(
            default_host=config.default_route_host,
            timeout_secs=config.upstream_timeout_secs,
            mock=config.mock_upstream)
        self.metrics = GatewayMetrics()
        self.ssl_context = build_server_context(
            config.tls_cert, config.tls_key, config.tls_ca,
            min_version=config.tls_min_version)
        self._server: Optional[asyncio.AbstractServer] = None
        self._clock_override: Optional[dt.datetime] = None  # для тестов TTL

    # ---------------------------------------------------------------- lifecycle
    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, host=self.config.listen, port=self.config.port,
            ssl=self.ssl_context)
        log.info("LLM Gateway listening on %s:%s (mTLS, TLS%s)",
                 self.config.listen, self.config.port, self.config.tls_min_version)

    async def serve_forever(self) -> None:
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        self.egress_log.close()
        self.audit.close()

    # ------------------------------------------------------------------ handler
    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            # -- Шаг 1: mTLS-авторизация (сертификат уже проверен OpenSSL: CA, цепочка)
            peer_cert = writer.get_extra_info("peercert")
            if not peer_cert:
                self.metrics.tls_rejected += 1
                log.warning("reject: клиент без сертификата (%s)", peer)
                return  # разрыв соединения (AC-08-семантика для mTLS)
            cn = subject_common_name(peer_cert)
            try:
                enforce_short_lived_ttl(peer_cert, self.config.client_cert_max_ttl_secs,
                                        now=self._clock_override)
            except MtlsPolicyError as exc:
                self.metrics.ttl_rejected += 1
                log.warning("reject: TTL-политика mTLS (%s): %s", cn or peer, exc)
                await self._send(writer, 495, {"error": "mtls_policy",
                                               "detail": str(exc)}, close=True)
                return

            # -- HTTP-разбор
            request = await asyncio.wait_for(
                self._read_request(reader), timeout=self.config.request_timeout_secs)
            if request is None:
                return
            method, path, headers, body = request
            self.metrics.requests_total += 1

            if method == "GET" and path == "/healthz":
                await self._send(writer, 200, {"status": "ok",
                                               "requests_total": self.metrics.requests_total,
                                               "client": cn})
                return
            if method == "GET" and path == "/metrics":
                text = self.metrics.render_prometheus(
                    self.breakers.snapshots(), self.limiter.stats)
                await self._send_raw(writer, 200, text.encode(),
                                     content_type="text/plain; version=0.0.4")
                return
            if method == "GET" and path == "/v1/allowlist":
                await self._send(writer, 200, {"allowlist": self.allowlist.entries()})
                return
            if not (method == "POST" and path == "/v1/chat/completions"):
                await self._send(writer, 404, {"error": "not_found",
                                               "allowed": ["POST /v1/chat/completions",
                                                            "GET /healthz", "GET /metrics"]})
                return

            await self._handle_chat_completions(writer, cn, body)
        except asyncio.TimeoutError:
            await self._send(writer, 408, {"error": "request_timeout"})
        except (ConnectionError, asyncio.IncompleteReadError) as exc:
            log.debug("connection error (%s): %s", peer, exc)
        except Exception as exc:  # noqa: BLE001 — gateway обязан выжить
            log.exception("internal error: %s", exc)
            try:
                await self._send(writer, 500, {"error": "internal_error"})
            except (ConnectionError, OSError):
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _handle_chat_completions(self, writer: asyncio.StreamWriter,
                                       client_cn: str, raw_body: bytes) -> None:
        started = time.monotonic()
        # -- разбор JSON-тела
        try:
            payload = json.loads(raw_body)
            if not isinstance(payload, dict):
                raise ValueError("body must be a JSON object")
        except (json.JSONDecodeError, ValueError) as exc:
            await self._send(writer, 400, {"error": "bad_request", "detail": str(exc)})
            return

        # -- Шаг 2: rate-limit по CN
        decision = self.limiter.allow(client_cn or "anonymous")
        if not decision.allowed:
            self.metrics.rate_limited += 1
            await self._send(writer, 429,
                             {"error": "rate_limited",
                              "retry_after_secs": round(decision.retry_after_secs, 2)},
                             headers={"Retry-After": str(int(decision.retry_after_secs) + 1)})
            return

        # -- Шаг 3: Egress DLP (fail fast)
        messages = payload.get("messages") or []
        verdict = self.dlp.scan_messages(messages) if self.config.dlp_enabled else None
        model = str(payload.get("model", ""))
        if verdict is not None and verdict.blocked:
            self.metrics.dlp_blocked += 1
            self._log_egress("POST", self.router.route(payload)[0], model, client_cn,
                             raw_body, "BLOCK", verdict.reasons(), 451, started)
            await self._send(writer, 451,
                             {"error": "dlp_blocked",
                              "categories": verdict.reasons(),
                              "detail": "Egress DLP: запрос содержит PII/секреты/запрещённые "
                                        "фразы (F-D-04). Используйте локальную модель."})
            return

        # -- Шаг 4: allow-list доменов
        host, path = self.router.route(payload)
        if not self.allowlist.is_allowed(host):
            self.metrics.allowlist_denied += 1
            reason = explain_rejection(host, self.allowlist) or "not in allow-list"
            self._log_egress("POST", host, model, client_cn, raw_body,
                             "BLOCK_ALLOWLIST", [reason], 403, started)
            await self._send(writer, 403, {"error": "egress_forbidden", "detail": reason})
            return

        # -- Шаг 5: circuit breaker
        breaker = self.breakers.get(host)
        try:
            breaker.acquire()
        except CircuitOpenError as exc:
            self.metrics.breaker_rejected += 1
            await self._send(writer, 503,
                             {"error": "circuit_open",
                              "upstream": host,
                              "retry_after_secs": round(exc.retry_after, 2),
                              "fallback": "локальная модель Qwen 2.5 (route=local)"},
                             headers={"Retry-After": str(int(exc.retry_after) + 1)})
            return

        # -- Шаг 6: upstream
        try:
            result = await self.router.forward(host, path, payload)
        except UpstreamError as exc:
            breaker.record_failure()
            self.metrics.upstream_errors += 1
            self._log_egress("POST", host, model, client_cn, raw_body,
                             "UPSTREAM_ERROR", [str(exc)], 502, started)
            await self._send(writer, 502, {"error": "upstream_error",
                                           "upstream": host, "detail": str(exc)})
            return
        except (OSError, asyncio.TimeoutError) as exc:
            breaker.record_failure()
            self.metrics.upstream_errors += 1
            self._log_egress("POST", host, model, client_cn, raw_body,
                             "UPSTREAM_ERROR", [str(exc)], 504, started)
            await self._send(writer, 504, {"error": "upstream_timeout",
                                           "upstream": host})
            return
        breaker.record_success()
        self.metrics.upstream_ok += 1

        # -- Шаг 7: DLP-скан ответа (defense in depth)
        response_bytes = json.dumps(result.body, ensure_ascii=False).encode("utf-8")
        if self.config.dlp_enabled:
            answer_text = _extract_answer_text(result.body)
            resp_verdict = self.dlp.scan(answer_text, fail_fast=False)
            if resp_verdict.blocked:
                self.metrics.dlp_blocked += 1
                self._log_egress("POST", host, model, client_cn, raw_body,
                                 "BLOCK_RESPONSE", resp_verdict.reasons(),
                                 result.status, started)
                await self._send(writer, 451,
                                 {"error": "dlp_blocked_response",
                                  "categories": resp_verdict.reasons()})
                return

        # -- Шаг 8: egress WORM-лог + L7
        self._log_egress("POST", host, model, client_cn, raw_body, "PASS", [],
                         result.status, started)
        latency = (time.monotonic() - started) * 1000
        self.metrics.latency_sum_ms += latency

        # -- Шаг 9: ответ
        result.body.setdefault("zt_gateway", {})
        result.body["zt_gateway"].update({
            "provider": result.provider,
            "mocked": result.mocked,
            "latency_ms": round(latency, 2),
            "client": client_cn,
        })
        await self._send(writer, result.status, result.body)

    def _log_egress(self, method: str, host: str, model: str, client_cn: str,
                    payload: bytes, verdict: str, reasons: list, status: int,
                    started: float) -> None:
        latency_ms = (time.monotonic() - started) * 1000
        entry = self.egress_log.record(method=method, host=host, model=model,
                                       client_cn=client_cn, payload=payload,
                                       verdict=verdict, reasons=reasons,
                                       status=status, latency_ms=latency_ms)
        self.audit.append(
            kind="RECORD_KIND_EGRESS",
            payload=json.dumps({
                "method": method, "host": host, "model": model,
                "client_cn": client_cn, "payload_hash": entry["payload_hash"],
                "verdict": verdict, "reasons": reasons, "status": status,
                "latency_ms": entry["latency_ms"],
            }, ensure_ascii=False).encode("utf-8"),
            subject=client_cn)

    # --------------------------------------------------------------- HTTP utils
    async def _read_request(self, reader: asyncio.StreamReader
                            ) -> Optional[tuple[str, str, Dict[str, str], bytes]]:
        request_line = await reader.readline()
        if not request_line:
            return None
        try:
            method, path, _version = request_line.decode("latin-1").strip().split(" ", 2)
        except ValueError:
            return None
        headers: Dict[str, str] = {}
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            key, _, value = line.decode("latin-1").partition(":")
            headers[key.strip().lower()] = value.strip()
        body = b""
        length = int(headers.get("content-length", "0") or 0)
        if length > self.config.max_body_bytes:
            raise ValueError(f"body too large: {length} > {self.config.max_body_bytes}")
        if length:
            body = await reader.readexactly(length)
        return method.upper(), path, headers, body

    async def _send(self, writer: asyncio.StreamWriter, status: int,
                    payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None,
                    close: bool = False) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        await self._send_raw(writer, status, body,
                             content_type="application/json; charset=utf-8",
                             headers=headers, close=close)

    async def _send_raw(self, writer: asyncio.StreamWriter, status: int,
                        body: bytes, content_type: str = "application/json",
                        headers: Optional[Dict[str, str]] = None,
                        close: bool = False) -> None:
        reason = {200: "OK", 400: "Bad Request", 403: "Forbidden",
                  404: "Not Found", 408: "Request Timeout",
                  429: "Too Many Requests", 451: "Unavailable For Legal Reasons",
                  495: "SSL Certificate Error", 500: "Internal Server Error",
                  502: "Bad Gateway", 503: "Service Unavailable",
                  504: "Gateway Timeout"}.get(status, "Error")
        head = (f"HTTP/1.1 {status} {reason}\r\n"
                f"Server: {SERVER_HEADER}\r\n"
                f"Content-Type: {content_type}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"X-Content-Type-Options: nosniff\r\n")
        for key, value in (headers or {}).items():
            head += f"{key}: {value}\r\n"
        head += "\r\n"
        writer.write(head.encode("latin-1") + body)
        await writer.drain()
        if close:
            writer.close()


def _extract_answer_text(body: Dict[str, Any]) -> str:
    parts = []
    for choice in body.get("choices") or []:
        if isinstance(choice, dict):
            message = choice.get("message") or {}
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                parts.append(message["content"])
    if isinstance(body.get("content"), str):
        parts.append(body["content"])
    return "\n".join(parts)


async def run_gateway(config: GatewayConfig) -> None:
    server = GatewayServer(config)
    await server.start()
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _request_stop(*_args: Any) -> None:
        log.info("останов по сигналу")
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _request_stop)
        except (NotImplementedError, RuntimeError):
            pass  # Windows/ограниченные среды — Ctrl-C обработает KeyboardInterrupt
    serve_task = asyncio.create_task(server.serve_forever())
    await stop_event.wait()
    serve_task.cancel()
    try:
        await serve_task
    except asyncio.CancelledError:
        pass
    await server.stop()
