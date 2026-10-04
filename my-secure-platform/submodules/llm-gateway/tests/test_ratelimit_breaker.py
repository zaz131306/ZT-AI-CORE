"""Тесты rate limiter и circuit breaker (F-D-04)."""
from __future__ import annotations

import pytest

from llm_gateway.breaker import BreakerState, CircuitBreaker, CircuitOpenError
from llm_gateway.ratelimit import FixedWindowCounter, TokenBucketLimiter


class FakeClock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, secs):
        self.t += secs


# ---------------------------------------------------------------- rate limit

def test_token_bucket_allows_burst_then_limits():
    clock = FakeClock()
    limiter = TokenBucketLimiter(rate_per_min=60, burst=5, clock=clock)
    for _ in range(5):
        assert limiter.allow("d8").allowed
    denied = limiter.allow("d8")
    assert not denied.allowed
    assert denied.retry_after_secs > 0


def test_token_bucket_refills_over_time():
    clock = FakeClock()
    limiter = TokenBucketLimiter(rate_per_min=60, burst=2, clock=clock)
    assert limiter.allow("x").allowed
    assert limiter.allow("x").allowed
    assert not limiter.allow("x").allowed
    clock.advance(1.0)  # 60/мин = 1 токен/сек
    assert limiter.allow("x").allowed
    assert not limiter.allow("x").allowed


def test_token_bucket_isolated_per_subject():
    clock = FakeClock()
    limiter = TokenBucketLimiter(rate_per_min=6, burst=1, clock=clock)
    assert limiter.allow("a").allowed
    assert not limiter.allow("a").allowed
    assert limiter.allow("b").allowed, "субъекты изолированы"


def test_purge_idle_buckets():
    clock = FakeClock()
    limiter = TokenBucketLimiter(rate_per_min=60, burst=1, clock=clock)
    limiter.allow("old")
    clock.advance(7200)
    assert limiter.purge_idle(max_idle_secs=3600) == 1


def test_fixed_window_counter():
    clock = FakeClock(t=1000.0)
    fw = FixedWindowCounter(limit_per_min=2, clock=clock)
    assert fw.allow("k").allowed
    assert fw.allow("k").allowed
    assert not fw.allow("k").allowed
    clock.advance(61)
    assert fw.allow("k").allowed


def test_invalid_rate():
    with pytest.raises(ValueError):
        TokenBucketLimiter(rate_per_min=0)


# ---------------------------------------------------------------- circuit breaker

def test_breaker_trips_after_threshold():
    clock = FakeClock()
    b = CircuitBreaker("prov", fail_threshold=3, reset_timeout=10, clock=clock)
    assert b.state == BreakerState.CLOSED
    for _ in range(3):
        b.acquire()
        b.record_failure()
    assert b.state == BreakerState.OPEN
    with pytest.raises(CircuitOpenError):
        b.acquire()


def test_breaker_half_open_after_timeout():
    clock = FakeClock()
    b = CircuitBreaker("prov", fail_threshold=1, reset_timeout=5,
                       half_open_max=1, clock=clock)
    b.acquire(); b.record_failure()
    assert b.state == BreakerState.OPEN
    clock.advance(6)
    assert b.state == BreakerState.HALF_OPEN
    b.acquire()  # пробный запрос проходит


def test_breaker_closes_after_successful_probes():
    clock = FakeClock()
    b = CircuitBreaker("prov", fail_threshold=1, reset_timeout=1,
                       half_open_max=2, clock=clock)
    b.acquire(); b.record_failure()
    clock.advance(2)
    b.acquire(); b.record_success()
    b.acquire(); b.record_success()
    assert b.state == BreakerState.CLOSED


def test_breaker_reopens_on_half_open_failure():
    clock = FakeClock()
    b = CircuitBreaker("prov", fail_threshold=1, reset_timeout=1, clock=clock)
    b.acquire(); b.record_failure()
    clock.advance(2)
    assert b.state == BreakerState.HALF_OPEN
    b.acquire(); b.record_failure()
    assert b.state == BreakerState.OPEN


def test_breaker_success_resets_failure_counter():
    clock = FakeClock()
    b = CircuitBreaker("prov", fail_threshold=3, reset_timeout=10, clock=clock)
    b.acquire(); b.record_failure()
    b.acquire(); b.record_failure()
    b.acquire(); b.record_success()   # сброс счётчика
    b.acquire(); b.record_failure()
    b.acquire(); b.record_failure()
    assert b.state == BreakerState.CLOSED
    b.acquire(); b.record_failure()
    assert b.state == BreakerState.OPEN


def test_breaker_half_open_limits_inflight():
    clock = FakeClock()
    b = CircuitBreaker("prov", fail_threshold=1, reset_timeout=1,
                       half_open_max=1, clock=clock)
    b.acquire(); b.record_failure()
    clock.advance(2)
    b.acquire()  # 1 пробный разрешён
    with pytest.raises(CircuitOpenError):
        b.acquire()  # второй — отклонён до исхода первого
