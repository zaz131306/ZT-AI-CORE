"""Ed25519-подпись индекса KB (Tampering-контрмера, Раздел 2.2).

Подписывается BLAKE3-дайджест канонического представления индекса
(отсортированный список {chunk_id, content_hash}). Приватный ключ в prod —
в TPM/HSM (F-H-03); здесь — файловый/dev-провайдер через `cryptography`
(опциональная зависимость; без неё индекс остаётся неподписанным, что
фиксируется в Health-ответе).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List, Optional

from .store import StoredChunk

try:  # pragma: no cover - опциональная зависимость
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    CRYPTO_AVAILABLE = False

try:
    import blake3 as _blake3

    def _digest(data: bytes) -> bytes:
        return _blake3.blake3(data).digest()
except ImportError:  # pragma: no cover
    import hashlib

    def _digest(data: bytes) -> bytes:
        return hashlib.blake2b(data, digest_size=32).digest()


@dataclass(frozen=True)
class IndexSignature:
    index_digest: str
    signature_hex: Optional[str]
    public_key_hex: Optional[str]
    algorithm: str = "Ed25519+BLAKE3"


def canonical_index(chunks: List[StoredChunk]) -> bytes:
    entries = sorted(
        ({"chunk_id": c.chunk_id, "content_hash": c.content_hash,
          "doc_id": c.doc_id, "ordinal": c.ordinal} for c in chunks),
        key=lambda e: e["chunk_id"],
    )
    return json.dumps(entries, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def index_digest(chunks: List[StoredChunk]) -> str:
    return _digest(canonical_index(chunks)).hex()


class IndexSigner:
    """Подписант индекса. key_path=None → неподписанный режим (dev без crypto)."""

    def __init__(self, key_path: Optional[str] = None):
        self._private: Optional[object] = None
        self.key_path = key_path
        if key_path and CRYPTO_AVAILABLE:
            with open(key_path, "rb") as fh:
                self._private = serialization.load_pem_private_key(fh.read(), password=None)

    @staticmethod
    def generate_dev_key(path: str) -> str:
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography недоступен — подпись индекса невозможна")
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        with open(path, "wb") as fh:
            fh.write(pem)
        import os
        os.chmod(path, 0o600)
        return path

    def sign(self, chunks: List[StoredChunk]) -> IndexSignature:
        digest = index_digest(chunks)
        if self._private is None or not CRYPTO_AVAILABLE:
            return IndexSignature(index_digest=digest, signature_hex=None,
                                  public_key_hex=None)
        sig = self._private.sign(bytes.fromhex(digest))  # type: ignore[attr-defined]
        pub = self._private.public_key()  # type: ignore[attr-defined]
        pub_bytes = pub.public_bytes(serialization.Encoding.Raw,
                                     serialization.PublicFormat.Raw)
        return IndexSignature(index_digest=digest, signature_hex=sig.hex(),
                              public_key_hex=pub_bytes.hex())


def verify_index_signature(chunks: List[StoredChunk], signature: IndexSignature) -> bool:
    if not CRYPTO_AVAILABLE or signature.signature_hex is None \
            or signature.public_key_hex is None:
        return False
    if index_digest(chunks) != signature.index_digest:
        return False
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signature.public_key_hex))
    try:
        pub.verify(bytes.fromhex(signature.signature_hex),
                   bytes.fromhex(signature.index_digest))
        return True
    except InvalidSignature:
        return False
