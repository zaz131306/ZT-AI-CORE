"""ZT-AI-CORE LLM Gateway (L4/D4) — единственный легальный egress для D8.

F-D-04: mTLS (TTL ≤ 5 мин) · Egress DLP (PII/ключи) · Rate-Limit ·
Circuit Breaker · allow-list доменов · собственный WORM-лог egress.
"""
from __future__ import annotations

__version__ = "2.4.0"

from .config import GatewayConfig
from .dlp import DlpAction, DlpCategory, DlpScanner, DlpVerdict
from .ratelimit import TokenBucketLimiter
from .breaker import BreakerState, CircuitBreaker, CircuitOpenError
from .allowlist import DomainAllowlist
from .mtls import build_client_context, build_server_context, enforce_short_lived_ttl
from .server import GatewayServer, run_gateway

__all__ = [
    "GatewayConfig",
    "GatewayServer",
    "run_gateway",
    "DlpScanner",
    "DlpVerdict",
    "DlpAction",
    "DlpCategory",
    "TokenBucketLimiter",
    "CircuitBreaker",
    "BreakerState",
    "CircuitOpenError",
    "DomainAllowlist",
    "build_server_context",
    "build_client_context",
    "enforce_short_lived_ttl",
]
