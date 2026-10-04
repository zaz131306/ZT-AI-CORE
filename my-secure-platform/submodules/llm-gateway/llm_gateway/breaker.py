"""Circuit Breaker (F-D-04): CLOSED → OPEN → HALF_OPEN.

Защита апстрим-провайдеров и D8 от каскадных отказов; при OPEN egress
немедленно возвращает 503 + рекомендацию fallback на локальный Qwen
(Chaos-сценарий E: kill -9 LLM Gateway → circuit breaker на повторах).
"""
from __future__ import annotations

import threading
import time
from enum import Enum
from typing import Callable, Dict


class BreakerState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitOpenError(RuntimeError):
    def __init__(self, name: str, retry_after: float):
        super().__init__(
            f"circuit '{name}' OPEN; retry_after={retry_after:.1f}s "
            "(используйте локальную модель — fallback Qwen 2.5)")
        self.name = name
        self.retry_after = retry_after


class CircuitBreaker:
    def __init__(self, name: str, fail_threshold: int = 5,
                 reset_timeout: float = 30.0, half_open_max: int = 2,
                 clock: Callable[[], float] = time.monotonic):
        if fail_threshold < 1:
            raise ValueError("fail_threshold must be >= 1")
        self.name = name
        self.fail_threshold = fail_threshold
        self.reset_timeout = reset_timeout
        self.half_open_max = max(1, half_open_max)
        self._clock = clock
        self._lock = threading.Lock()
        self._state = BreakerState.CLOSED
        self._failures = 0
        self._opened_at = 0.0
        self._half_open_inflight = 0
        self._half_open_successes = 0
        self.stats_counters = {"closed_calls": 0, "rejected": 0,
                               "failures": 0, "successes": 0, "trips": 0}

    # --- состояние -----------------------------------------------------------------
    @property
    def state(self) -> BreakerState:
        with self._lock:
            self._maybe_half_open_locked()
            return self._state

    def _maybe_half_open_locked(self) -> None:
        if self._state == BreakerState.OPEN:
            if self._clock() - self._opened_at >= self.reset_timeout:
                self._state = BreakerState.HALF_OPEN
                self._half_open_inflight = 0
                self._half_open_successes = 0

    # --- допуск запроса --------------------------------------------------------------
    def acquire(self) -> None:
        """Разрешить запрос или raise CircuitOpenError."""
        with self._lock:
            self._maybe_half_open_locked()
            if self._state == BreakerState.OPEN:
                retry_after = max(0.0, self.reset_timeout
                                  - (self._clock() - self._opened_at))
                self.stats_counters["rejected"] += 1
                raise CircuitOpenError(self.name, retry_after)
            if self._state == BreakerState.HALF_OPEN:
                if self._half_open_inflight >= self.half_open_max:
                    self.stats_counters["rejected"] += 1
                    raise CircuitOpenError(self.name, self.reset_timeout)
                self._half_open_inflight += 1
            self.stats_counters["closed_calls"] += 1

    # --- исходы -----------------------------------------------------------------------
    def record_success(self) -> None:
        with self._lock:
            self.stats_counters["successes"] += 1
            if self._state == BreakerState.HALF_OPEN:
                self._half_open_inflight = max(0, self._half_open_inflight - 1)
                self._half_open_successes += 1
                if self._half_open_successes >= self.half_open_max:
                    self._state = BreakerState.CLOSED
                    self._failures = 0
            elif self._state == BreakerState.CLOSED:
                self._failures = 0

    def record_failure(self) -> None:
        with self._lock:
            self.stats_counters["failures"] += 1
            if self._state == BreakerState.HALF_OPEN:
                self._half_open_inflight = max(0, self._half_open_inflight - 1)
                self._trip_locked()
            else:
                self._failures += 1
                if self._failures >= self.fail_threshold:
                    self._trip_locked()

    def _trip_locked(self) -> None:
        self._state = BreakerState.OPEN
        self._opened_at = self._clock()
        self._failures = 0
        self.stats_counters["trips"] += 1

    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            self._maybe_half_open_locked()
            return {
                "name": self.name,
                "state": self._state.value,
                "failures": self._failures,
                **self.stats_counters,
            }


class BreakerRegistry:
    """По одному breaker'у на апстрим-хост."""

    def __init__(self, fail_threshold: int, reset_timeout: float, half_open_max: int,
                 clock: Callable[[], float] = time.monotonic):
        self._factory = lambda name: CircuitBreaker(
            name, fail_threshold, reset_timeout, half_open_max, clock)
        self._lock = threading.Lock()
        self._items: Dict[str, CircuitBreaker] = {}

    def get(self, name: str) -> CircuitBreaker:
        with self._lock:
            if name not in self._items:
                self._items[name] = self._factory(name)
            return self._items[name]

    def snapshots(self) -> Dict[str, Dict[str, object]]:
        with self._lock:
            return {name: b.snapshot() for name, b in self._items.items()}
