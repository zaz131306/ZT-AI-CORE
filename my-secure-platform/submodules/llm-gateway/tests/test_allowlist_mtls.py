"""Тесты allow-list доменов и mTLS-политики (F-D-04)."""
from __future__ import annotations

import datetime as dt

import pytest

from llm_gateway.allowlist import (
    AllowlistError,
    DomainAllowlist,
    explain_rejection,
    normalize_hostname,
)
from llm_gateway.mtls import (
    MtlsPolicyError,
    cert_window,
    enforce_short_lived_ttl,
    parse_ssl_date,
    subject_common_name,
)


# ---------------------------------------------------------------- allowlist

def test_exact_and_subdomain_match():
    al = DomainAllowlist(["api.provider-one.example"])
    assert al.is_allowed("api.provider-one.example")
    assert not al.is_allowed("provider-one.example")


def test_subdomain_allowed_by_default_entry():
    al = DomainAllowlist(["provider.example"])
    assert al.is_allowed("provider.example")
    assert al.is_allowed("api.provider.example")
    assert al.is_allowed("eu.api.provider.example")


def test_wildcard_only_subdomains():
    al = DomainAllowlist(["*.provider.example"])
    assert al.is_allowed("api.provider.example")
    assert not al.is_allowed("provider.example"), "apex не входит в *.domain"


def test_suffix_attack_rejected():
    al = DomainAllowlist(["provider.example"])
    for evil in [
        "provider.example.evil.tld",
        "notprovider.example",
        "evilprovider.example",
        "provider-example.tld",
    ]:
        assert not al.is_allowed(evil), evil


def test_url_normalization_and_port():
    al = DomainAllowlist(["api.provider.example"])
    assert al.is_allowed("https://api.provider.example/v1/chat")
    assert al.is_allowed("api.provider.example:8443")
    assert al.is_allowed("HTTPS://API.Provider.Example./path?x=1#frag")


def test_userinfo_trick_rejected():
    with pytest.raises(AllowlistError, match="userinfo"):
        normalize_hostname("https://api.provider.example@evil.tld/path")
    al = DomainAllowlist(["api.provider.example"])
    assert not al.is_allowed("api.provider.example@evil.tld")


def test_ip_literals_only_if_listed():
    al = DomainAllowlist(["api.provider.example"])
    assert not al.is_allowed("93.184.216.34")
    al2 = DomainAllowlist(["10.8.0.5"])
    assert al2.is_allowed("10.8.0.5")
    assert not al2.is_allowed("10.8.0.6")


def test_empty_allowlist_rejected():
    with pytest.raises(AllowlistError, match="пуст"):
        DomainAllowlist([])


def test_explain_rejection_message():
    al = DomainAllowlist(["api.ok.example"])
    reason = explain_rejection("https://bad.example/x", al)
    assert reason and "allow-list" in reason
    assert explain_rejection("api.ok.example", al) is None


# ---------------------------------------------------------------- mTLS policy

CERT_5MIN = {
    "notBefore": "Jun  5 11:55:00 2026 GMT",
    "notAfter": "Jun  5 12:00:00 2026 GMT",
    "subject": ((( "commonName", "d8-rag-core"),),),
}
CERT_1DAY = {
    "notBefore": "Jun  5 12:00:00 2026 GMT",
    "notAfter": "Jun  6 12:00:00 2026 GMT",
    "subject": ((("commonName", "d8-violator"),),),
}


def _at(*args) -> dt.datetime:
    return dt.datetime(*args, tzinfo=dt.timezone.utc)


def test_parse_ssl_date():
    parsed = parse_ssl_date("Jun  5 12:00:00 2026 GMT")
    assert parsed == _at(2026, 6, 5, 12, 0, 0)
    with pytest.raises(MtlsPolicyError):
        parse_ssl_date("not a date")


def test_cert_window_ttl():
    w = cert_window(CERT_5MIN)
    assert w.ttl == dt.timedelta(minutes=5)
    w2 = cert_window(CERT_1DAY)
    assert w2.ttl == dt.timedelta(days=1)


def test_short_lived_5min_accepted():
    now = _at(2026, 6, 5, 11, 57, 0)
    w = enforce_short_lived_ttl(CERT_5MIN, max_ttl_secs=300, now=now)
    assert w.ttl.total_seconds() == 300


def test_long_lived_cert_rejected_even_if_valid():
    now = _at(2026, 6, 5, 13, 0, 0)
    with pytest.raises(MtlsPolicyError, match="TTL"):
        enforce_short_lived_ttl(CERT_1DAY, max_ttl_secs=300, now=now)


def test_expired_cert_rejected():
    now = _at(2026, 6, 5, 12, 30, 0)  # после notAfter
    with pytest.raises(MtlsPolicyError, match="истёк"):
        enforce_short_lived_ttl(CERT_5MIN, max_ttl_secs=300, now=now)


def test_not_yet_valid_cert_rejected():
    now = _at(2026, 6, 5, 11, 0, 0)  # до notBefore
    with pytest.raises(MtlsPolicyError, match="не действителен"):
        enforce_short_lived_ttl(CERT_5MIN, max_ttl_secs=300, now=now)


def test_subject_cn_extraction():
    assert subject_common_name(CERT_5MIN) == "d8-rag-core"
    assert subject_common_name({}) == ""
