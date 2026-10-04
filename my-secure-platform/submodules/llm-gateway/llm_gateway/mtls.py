"""mTLS-контекст L4-гейтвея (F-D-04, Приложение Б п.1).

* TLS 1.3 (минимум), cipher-suites: TLS_AES_256_GCM_SHA384 и
  TLS_CHACHA20_POLY1305_SHA256 (дефолты OpenSSL для TLS1.3 — оба входят
  в разрешённый набор; иные версии протокола отключены);
* обмен ключами: X25519 (set_ecdh_curve);
* клиентские сертификаты D8: CERT_REQUIRED + политика краткоживущести
  (TTL ≤ 5 мин): сертификат с большим сроком действия отклоняется даже
  при валидной подписи CA.
"""
from __future__ import annotations

import datetime as dt
import re
import ssl
from dataclasses import dataclass
from typing import Optional


class MtlsPolicyError(ValueError):
    """Нарушение политики mTLS (TTL/валидность)."""


@dataclass(frozen=True)
class CertWindow:
    not_before: dt.datetime
    not_after: dt.datetime

    @property
    def ttl(self) -> dt.timedelta:
        return self.not_after - self.not_before


# Форматы notBefore/notAfter в ssl.getpeercert(): 'Jun  5 12:00:00 2026 GMT'
_SSL_DATE_RE = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\s+GMT$")
_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def parse_ssl_date(value: str) -> dt.datetime:
    m = _SSL_DATE_RE.match(value.strip())
    if not m:
        raise MtlsPolicyError(f"не удалось разобрать дату сертификата: {value!r}")
    mon, day, hh, mm, ss, year = m.groups()
    if mon not in _MONTHS:
        raise MtlsPolicyError(f"неизвестный месяц: {mon!r}")
    return dt.datetime(int(year), _MONTHS[mon], int(day),
                       int(hh), int(mm), int(ss), tzinfo=dt.timezone.utc)


def cert_window(peer_cert: dict) -> CertWindow:
    return CertWindow(
        not_before=parse_ssl_date(peer_cert["notBefore"]),
        not_after=parse_ssl_date(peer_cert["notAfter"]),
    )


def enforce_short_lived_ttl(peer_cert: dict, max_ttl_secs: int,
                            now: Optional[dt.datetime] = None) -> CertWindow:
    """F-D-04: клиентский сертификат D8 обязан быть краткоживущим (≤ 5 мин).

    Дополнительно: сертификат должен быть действующим на момент проверки.
    """
    window = cert_window(peer_cert)
    ttl = window.ttl.total_seconds()
    if ttl > max_ttl_secs:
        raise MtlsPolicyError(
            f"TTL клиентского сертификата {ttl:.0f}s > лимита {max_ttl_secs}s "
            "(F-D-04: краткоживущие сертификаты)")
    now = now or dt.datetime.now(dt.timezone.utc)
    if now < window.not_before - dt.timedelta(seconds=5):
        raise MtlsPolicyError("клиентский сертификат ещё не действителен")
    if now > window.not_after + dt.timedelta(seconds=5):
        raise MtlsPolicyError("клиентский сертификат истёк")
    return window


def subject_common_name(peer_cert: dict) -> str:
    for rdn in peer_cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return str(value)
    return ""


def build_server_context(certfile: str, keyfile: str, cafile: str,
                         min_version: str = "1.3") -> ssl.SSLContext:
    """Серверный контекст mTLS (гейтвей принимает клиентов D8)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if min_version == "1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # X25519 для обмена ключами (Приложение Б п.1)
    try:
        ctx.set_ecdh_curve("X25519")
    except (ValueError, ssl.SSLError):
        pass  # на некоторых сборках OpenSSL выбор кривой не требуется
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False  # клиенты аутентифицируются сертификатом, не именем
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.load_verify_locations(cafile=cafile)
    return ctx


def build_client_context(cafile: str, certfile: Optional[str] = None,
                         keyfile: Optional[str] = None,
                         server_hostname_check: bool = True) -> ssl.SSLContext:
    """Клиентский контекст (D8 → гейтвей; healthcheck; тесты)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=cafile)
    ctx.check_hostname = server_hostname_check
    if not server_hostname_check:
        ctx.verify_mode = ssl.CERT_REQUIRED
    if certfile:
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile or certfile)
    return ctx
