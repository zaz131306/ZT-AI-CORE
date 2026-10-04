"""Token-bucket rate limiter (F-D-04: N запросов/мин на субъекта)."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


@dataclass
class RateLimitDecision:
    allowed: bool
    retry_after_secs: float = 0.0
    remaining: float = 0.0


class TokenBucketLimiter:
    """Классический token bucket: capacity = burst, refill = rate/60 в сек.

    Потокобезопасен (gateway обслуживает соединения в event loop + тредах).
    """

    def __init__(self, rate_per_min: int, burst: int | None = None,
                 clock=time.monotonic):
        if rate_per_min <= 0:
            raise ValueError("rate_per_min must be positive")
        self.rate_per_sec = rate_per_min / 60.0
        self.capacity = float(burst if burst is not None else max(1, rate_per_min // 6))
        self._clock = clock
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self._total_allowed = 0
        self._total_denied = 0

    def allow(self, key: str, cost: float = 1.0) -> RateLimitDecision:
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=self.capacity, last_refill=now)
                self._buckets[key] = bucket
            elapsed = max(0.0, now - bucket.last_refill)
            bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.rate_per_sec)
            bucket.last_refill = now
            if bucket.tokens >= cost:
                bucket.tokens -= cost
                self._total_allowed += 1
                return RateLimitDecision(True, 0.0, bucket.tokens)
            deficit = cost - bucket.tokens
            retry_after = deficit / self.rate_per_sec
            self._total_denied += 1
            return RateLimitDecision(False, retry_after, bucket.tokens)

    def purge_idle(self, max_idle_secs: float = 3600.0) -> int:
        """Очистка простаивающих бакетов (защита памяти от churn субъектов)."""
        now = self._clock()
        with self._lock:
            stale = [k for k, b in self._buckets.items()
                     if now - b.last_refill > max_idle_secs]
            for k in stale:
                del self._buckets[k]
            return len(stale)

    @property
    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "allowed": self._total_allowed,
                "denied": self._total_denied,
                "subjects": len(self._buckets),
            }


class FixedWindowCounter:
    """Альтернатива: фиксированное окно (N/мин) — для отчётности по минутам."""

    def __init__(self, limit_per_min: int, clock=time.time):
        self.limit = limit_per_min
        self._clock = clock
        self._windows: Dict[str, tuple] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> RateLimitDecision:
        minute = int(self._clock() // 60)
        with self._lock:
            stored_minute, count = self._windows.get(key, (minute, 0))
            if stored_minute != minute:
                stored_minute, count = minute, 0
            if count >= self.limit:
                retry_after = 60.0 - (self._clock() % 60.0)
                return RateLimitDecision(False, retry_after, 0.0)
            self._windows[key] = (minute, count + 1)
            return RateLimitDecision(True, 0.0, float(self.limit - count - 1))
