"""Общие фикстуры: сертификаты для mTLS-тестов (CA, сервер, клиенты)."""
from __future__ import annotations

import datetime as dt
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID


def _write(path: Path, data: bytes) -> str:
    path.write_bytes(data)
    path.chmod(0o600)
    return str(path)


def _gen_ca(tmp: Path, prefix: str = "ca"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZT-AI-CORE"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ZT Test CA"),
    ])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca_crt = _write(tmp / f"{prefix}.crt", cert.public_bytes(serialization.Encoding.PEM))
    ca_key = _write(tmp / f"{prefix}.key", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return ca_crt, ca_key, key, cert


def _gen_leaf(ca_key, ca_cert, cn: str, ttl: dt.timedelta, tmp: Path,
              prefix: str, server: bool, key_algo: str = "ed25519"):
    if key_algo == "ed25519":
        key = ed25519.Ed25519PrivateKey.generate()
    else:
        key = ec.generate_private_key(ec.SECP256R1())
    # Подписывает CA-ключ (EC P-256) — алгоритм хэша определяется ПОДПИСАНТОМ.
    sign_hash = hashes.SHA256()
    now = dt.datetime.now(dt.timezone.utc)
    # not_before с запасом −30 с (clock skew); ОКНО ДЕЙСТВИЯ ровно ttl,
    # чтобы «5-минутный» сертификат удовлетворял политике TTL ≤ 300 с (F-D-04).
    not_before = now - dt.timedelta(seconds=30)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZT-AI-CORE"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + ttl)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH if server
                 else x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False)
    )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                          x509.IPAddress(
                                              __import__("ipaddress").IPv4Address("127.0.0.1"))]),
            critical=False)
    cert = builder.sign(ca_key, sign_hash)
    crt = _write(tmp / f"{prefix}.crt", cert.public_bytes(serialization.Encoding.PEM))
    k = _write(tmp / f"{prefix}.key", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return crt, k


@pytest.fixture(scope="session")
def certs(tmp_path_factory) -> dict:
    tmp = tmp_path_factory.mktemp("zt-certs")
    ca_crt, ca_key, ca_key_obj, ca_cert_obj = _gen_ca(tmp)
    server_crt, server_key = _gen_leaf(
        ca_key_obj, ca_cert_obj, "llm-gateway", dt.timedelta(days=90),
        tmp, "server", server=True, key_algo="ec")
    # Клиент D8: TTL 5 минут (валиден по F-D-04)
    good_crt, good_key = _gen_leaf(
        ca_key_obj, ca_cert_obj, "d8-rag-core", dt.timedelta(minutes=5),
        tmp, "client-good", server=False)
    # Клиент-нарушитель: TTL 1 день (нарушение F-D-04)
    long_crt, long_key = _gen_leaf(
        ca_key_obj, ca_cert_obj, "d8-violator", dt.timedelta(days=1),
        tmp, "client-long", server=False)
    # Клиент чужого CA — не пройдёт mTLS
    other_ca_crt, other_ca_key, other_key_obj, other_cert_obj = _gen_ca(tmp, prefix="rogue-ca")
    rogue_crt, rogue_key = _gen_leaf(
        other_key_obj, other_cert_obj, "rogue", dt.timedelta(minutes=5),
        tmp, "client-rogue", server=False)
    return {
        "ca": ca_crt, "server_crt": server_crt, "server_key": server_key,
        "good_crt": good_crt, "good_key": good_key,
        "long_crt": long_crt, "long_key": long_key,
        "rogue_crt": rogue_crt, "rogue_key": rogue_key,
        "dir": str(tmp),
    }


@pytest.fixture()
def clean_env(monkeypatch):
    """Убрать влияния внешних env-переменных ZT_GATEWAY_* на тесты."""
    for key in list(os.environ):
        if key.startswith(("ZT_GATEWAY_", "ZT_BREAKER_")):
            monkeypatch.delenv(key, raising=False)
    return monkeypatch
