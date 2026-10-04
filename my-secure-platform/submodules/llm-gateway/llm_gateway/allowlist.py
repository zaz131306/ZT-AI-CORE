"""Жёсткий allow-list доменов egress (F-D-04).

Правила сопоставления:
  * ``example.com`` — точное совпадение И поддомены (``*.example.com``);
  * ``*.example.com`` — только поддомены ( apex не допускается );
  * IP-литералы допускаются только при явном внесении в список;
  * userinfo (``user@host``), порта и путей в hostname быть не должно —
    входящие строки нормализуются и валидируются (защита от
    ``allowed.com.evil.tld`` и ``evil.tld#allowed.com``).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.?$")


class AllowlistError(ValueError):
    pass


@dataclass(frozen=True)
class AllowlistEntry:
    raw: str
    domain: str
    wildcard_subdomains_only: bool

    def matches(self, hostname: str) -> bool:
        host = hostname.rstrip(".").lower()
        if self.wildcard_subdomains_only:
            return host.endswith("." + self.domain)
        return host == self.domain or host.endswith("." + self.domain)


def normalize_hostname(value: str) -> str:
    """Извлечь и нормализовать hostname из URL/host:port/host-строки."""
    text = value.strip().lower()
    if not text:
        raise AllowlistError("пустой hostname")
    # отбрасываем схему
    if "://" in text:
        text = text.split("://", 1)[1]
    # userinfo-trick: берём ПОСЛЕДНИЙ сегмент после '@'
    if "@" in text:
        raise AllowlistError(
            f"userinfo в hostname запрещён (возможная маскировка): {value!r}")
    # путь/query/fragment
    for sep in ("/", "?", "#"):
        text = text.split(sep, 1)[0]
    # порт
    if text.startswith("["):  # IPv6 [::1]:port
        end = text.find("]")
        if end == -1:
            raise AllowlistError(f"некорректный IPv6-литерал: {value!r}")
        host = text[1:end]
        rest = text[end + 1:]
        if rest and not rest.startswith(":"):
            raise AllowlistError(f"мусор после IPv6: {value!r}")
    elif ":" in text:
        host, _, port = text.partition(":")
        if port and not port.isdigit():
            raise AllowlistError(f"некорректный порт: {value!r}")
    else:
        host = text
    host = host.rstrip(".")
    if not host:
        raise AllowlistError(f"пустой hostname после нормализации: {value!r}")
    return host


def _validate_host_or_ip(host: str) -> None:
    try:
        ipaddress.ip_address(host)
        return  # IP-литерал — валиден
    except ValueError:
        pass
    if not _HOST_RE.match(host) or len(host) > 253:
        raise AllowlistError(f"некорректный hostname: {host!r}")


class DomainAllowlist:
    def __init__(self, entries: Iterable[str]):
        self._entries: List[AllowlistEntry] = []
        for raw in entries:
            item = raw.strip()
            if not item:
                continue
            wildcard = item.startswith("*.")
            base = item[2:] if wildcard else item
            base = normalize_hostname(base)
            _validate_host_or_ip(base)
            self._entries.append(AllowlistEntry(raw=item, domain=base,
                                               wildcard_subdomains_only=wildcard))
        if not self._entries:
            raise AllowlistError(
                "allow-list пуст: F-D-04 требует жёсткий allow-list доменов")

    def is_allowed(self, host_or_url: str) -> bool:
        try:
            host = normalize_hostname(host_or_url)
        except AllowlistError:
            return False
        return any(e.matches(host) for e in self._entries)

    def entries(self) -> List[str]:
        return [e.raw for e in self._entries]

    def __len__(self) -> int:
        return len(self._entries)


def explain_rejection(host_or_url: str, allowlist: DomainAllowlist) -> Optional[str]:
    """Человекочитаемая причина отказа (для WORM-лога egress)."""
    try:
        host = normalize_hostname(host_or_url)
    except AllowlistError as exc:
        return str(exc)
    if allowlist.is_allowed(host):
        return None
    return (f"host {host!r} не в allow-list {allowlist.entries()} "
            "(egress запрещён, F-D-04)")
