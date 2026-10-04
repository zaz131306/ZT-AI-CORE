"""Маршрутизация egress-запросов к апстрим-провайдерам (F-D-02).

Режимы:
  * mock (ZT_GATEWAY_MOCK_UPSTREAM=1) — детерминированный ответ для
    dev-контура/chaos-тестов (не требует сети, работает в compose);
  * real — HTTPS/1.1 POST к провайдеру из allow-list (TLS-верификация
    обязательна; в prod — mTLS + TPM Quote по F-H-05, подключение
    внешнего аттестатора — точка расширения `attest()`).
"""
from __future__ import annotations

import asyncio
import json
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


class UpstreamError(RuntimeError):
    def __init__(self, message: str, retryable: bool = True):
        super().__init__(message)
        self.retryable = retryable


@dataclass
class UpstreamResult:
    status: int
    body: Dict[str, Any]
    latency_ms: float
    provider: str
    mocked: bool = False


@dataclass
class UpstreamRouter:
    default_host: str
    timeout_secs: float = 30.0
    mock: bool = False
    model_routes: Dict[str, str] = field(default_factory=dict)
    client_ssl: Optional[ssl.SSLContext] = None

    def route(self, body: Dict[str, Any]) -> tuple[str, str]:
        """(host, path) для запроса; model → provider из таблицы маршрутов."""
        model = str(body.get("model", ""))
        host = self.model_routes.get(model, self.default_host)
        return host, "/v1/chat/completions"

    async def forward(self, host: str, path: str,
                      payload: Dict[str, Any]) -> UpstreamResult:
        if self.mock:
            return self._mock_response(host, payload)
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(raw)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("ascii") + raw
        started = time.monotonic()
        ctx = self.client_ssl or ssl.create_default_context()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 443, ssl=ctx),
                timeout=self.timeout_secs)
        except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
            raise UpstreamError(f"connect to {host}:443 failed: {exc}") from exc
        try:
            writer.write(request)
            await writer.drain()
            head = await asyncio.wait_for(reader.readline(), timeout=self.timeout_secs)
            if not head:
                raise UpstreamError(f"{host}: empty response")
            status = _parse_status(head.decode("latin-1"))
            headers: Dict[str, str] = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=self.timeout_secs)
                if line in (b"\r\n", b"\n", b""):
                    break
                key, _, value = line.decode("latin-1").partition(":")
                headers[key.strip().lower()] = value.strip()
            length = int(headers.get("content-length", "0") or 0)
            if length > 32 * 1024 * 1024:
                raise UpstreamError("upstream response too large", retryable=False)
            data = await asyncio.wait_for(reader.readexactly(length),
                                          timeout=self.timeout_secs) if length else b""
            try:
                body = json.loads(data) if data else {}
            except json.JSONDecodeError:
                body = {"raw": data.decode("utf-8", "replace")[:4096]}
            latency = (time.monotonic() - started) * 1000
            if status >= 500:
                raise UpstreamError(f"{host} returned {status}")
            return UpstreamResult(status=status, body=body,
                                  latency_ms=latency, provider=host)
        except asyncio.IncompleteReadError as exc:
            raise UpstreamError(f"{host}: incomplete read: {exc}") from exc
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass

    def _mock_response(self, host: str, payload: Dict[str, Any]) -> UpstreamResult:
        messages = payload.get("messages") or []
        last_user = next((m.get("content", "") for m in reversed(messages)
                          if isinstance(m, dict) and m.get("role") == "user"), "")
        started = time.monotonic()
        body = {
            "id": f"mock-{time.time_ns()}",
            "object": "chat.completion",
            "model": payload.get("model", "mock-external-llm"),
            "provider": host,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": (
                        f"[MOCK {host}] Эхо-ответ внешнего провайдера на запрос: "
                        f"{last_user[:200]}"
                    ),
                },
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": len(str(payload)) // 4,
                      "completion_tokens": 16, "total_tokens": 0},
        }
        body["usage"]["total_tokens"] = (body["usage"]["prompt_tokens"]
                                         + body["usage"]["completion_tokens"])
        return UpstreamResult(status=200, body=body,
                              latency_ms=(time.monotonic() - started) * 1000,
                              provider=host, mocked=True)


def _parse_status(line: str) -> int:
    parts = line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise UpstreamError(f"bad status line: {line!r}", retryable=False)
    try:
        return int(parts[1])
    except ValueError as exc:
        raise UpstreamError(f"bad status code: {line!r}", retryable=False) from exc
