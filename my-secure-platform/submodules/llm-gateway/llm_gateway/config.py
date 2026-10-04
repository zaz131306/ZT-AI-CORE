"""Конфигурация LLM Gateway (F-D-04) из env/CLI."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_list(name: str, default: List[str] | None = None) -> List[str]:
    raw = os.environ.get(name)
    if not raw:
        return list(default or [])
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass
class GatewayConfig:
    # --- сеть -----------------------------------------------------------------
    listen: str = "0.0.0.0"
    port: int = 8443

    # --- mTLS (F-D-04: TTL <= 5 мин) -------------------------------------------
    tls_cert: str = field(default_factory=lambda: _env("ZT_GATEWAY_TLS_CERT", "/etc/zt-core/keys/gateway-server.crt"))
    tls_key: str = field(default_factory=lambda: _env("ZT_GATEWAY_TLS_KEY", "/etc/zt-core/keys/gateway-server.key"))
    tls_ca: str = field(default_factory=lambda: _env("ZT_GATEWAY_CA", "/etc/zt-core/keys/zt-ca.crt"))
    client_cert_max_ttl_secs: int = field(
        default_factory=lambda: _env_int("ZT_GATEWAY_CLIENT_MAX_TTL_SECS", 300))
    # Минимальная версия TLS: 1.3 (Приложение Б п.1)
    tls_min_version: str = field(default_factory=lambda: _env("ZT_GATEWAY_TLS_MIN", "1.3"))

    # --- egress allow-list (F-D-04) ---------------------------------------------
    allowlist: List[str] = field(
        default_factory=lambda: _env_list("ZT_GATEWAY_ALLOWLIST", []))

    # --- rate limit (F-D-04) ------------------------------------------------------
    rate_limit_per_min: int = field(
        default_factory=lambda: _env_int("ZT_GATEWAY_RATE_LIMIT_PER_MIN", 60))
    rate_burst: int = field(default_factory=lambda: _env_int("ZT_GATEWAY_RATE_BURST", 10))

    # --- circuit breaker (F-D-04) --------------------------------------------------
    breaker_fail_threshold: int = field(
        default_factory=lambda: _env_int("ZT_BREAKER_FAIL_THRESHOLD", 5))
    breaker_reset_secs: float = field(
        default_factory=lambda: _env_float("ZT_BREAKER_RESET_SECS", 30.0))
    breaker_half_open_max: int = field(
        default_factory=lambda: _env_int("ZT_BREAKER_HALF_OPEN_MAX", 2))

    # --- upstream ------------------------------------------------------------------
    upstream_timeout_secs: float = field(
        default_factory=lambda: _env_float("ZT_GATEWAY_UPSTREAM_TIMEOUT", 30.0))
    mock_upstream: bool = field(
        default_factory=lambda: _env_bool("ZT_GATEWAY_MOCK_UPSTREAM", False))
    default_route_host: str = field(
        default_factory=lambda: _env("ZT_GATEWAY_DEFAULT_HOST", "api.provider-one.example"))

    # --- DLP -------------------------------------------------------------------------
    dlp_enabled: bool = field(default_factory=lambda: _env_bool("ZT_GATEWAY_DLP", True))
    dlp_extra_uuids: List[str] = field(
        default_factory=lambda: _env_list("ZT_GATEWAY_INTERNAL_UUIDS", []))

    # --- аудит/логирование (F-D-04: собственный WORM-лог egress) ----------------------
    audit_socket: str = field(default_factory=lambda: _env("ZT_GATEWAY_AUDIT_SOCKET", ""))
    egress_log: str = field(
        default_factory=lambda: _env("ZT_GATEWAY_EGRESS_LOG", "/var/log/zt-core/egress.jsonl"))

    # --- операционное ------------------------------------------------------------------
    max_body_bytes: int = field(
        default_factory=lambda: _env_int("ZT_GATEWAY_MAX_BODY", 2 * 1024 * 1024))
    request_timeout_secs: float = field(
        default_factory=lambda: _env_float("ZT_GATEWAY_REQUEST_TIMEOUT", 60.0))

    @classmethod
    def from_env(cls) -> "GatewayConfig":
        return cls()

    def validate(self) -> List[str]:
        """Список проблем конфигурации (пусто — всё в порядке)."""
        problems: List[str] = []
        if self.client_cert_max_ttl_secs > 300:
            problems.append(
                f"client_cert_max_ttl_secs={self.client_cert_max_ttl_secs} > 300 "
                "(F-D-04: TTL ≤ 5 мин)")
        if not self.allowlist:
            problems.append("allow-list доменов пуст (F-D-04 требует жёсткий allow-list)")
        if self.rate_limit_per_min <= 0:
            problems.append("rate_limit_per_min должен быть > 0")
        for f_ in (self.tls_cert, self.tls_key, self.tls_ca):
            if not f_:
                problems.append("mTLS: cert/key/ca пути не заданы")
        return problems
