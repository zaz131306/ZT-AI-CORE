"""Эмбеддинги и векторное хранилище KB (F-B-01/02).

Прод: BGE-M3 / e5-small (локальные, eagerly-загруженные в bootstrap).
Dev/CI: детерминированный HashingEmbedder (feature hashing, stdlib) —
позволяет полноценно тестировать пайплайн без тяжёлых моделей; порог
cos-sim каскадного валидатора остаётся тем же (0.85/0.60).

Векторное хранилище: InMemoryVectorStore ( cosine-поиск перебором —
достаточно для KB ≤ 100k чанков на Edge; prod-адаптеры ChromaDB/pgvector
подключаются через тот же интерфейс `VectorStore`).
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol, Sequence, Tuple

_TOKEN_RE = re.compile(r"[\w\-]+", re.UNICODE)
_STOPWORDS = frozenset("""
и в во не что он на я с со как а то все она так его но да ты к у же вы за бы по
только ее мне было вот от меня еще нет о из ему теперь когда даже ну вдруг ли
если уже или ни быть был него до вас нибудь опять уж вам сказал ведь потом
себя ничего ей может они тут где есть надо ней для мы тебя их чем была сам
чтоб без будто чего раз тоже себе под будет ж тогда кто этот того потому этого
какой совсем ним здесь этом один почти мой тем чтобы нее сейчас были куда
зачем всех никогда можно при наконец два об другой хоть после над больше тот
через эти нас про всего них какая много разве три эту моя впрочем хорошо свою
этой перед иногда лучше чуть том нельзя такой им более всегда конечно всю
между это the of and for with that this from are was were be been have has
not you your it its his her their our
""".split())


def tokenize(text: str) -> List[str]:
    """Нормализованные токены: lower, без стоп-слов и пунктуации."""
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS]


class Embedder(Protocol):
    dim: int

    def embed(self, text: str) -> List[float]: ...

    def embed_batch(self, texts: Sequence[str]) -> List[List[float]]: ...

    @property
    def name(self) -> str: ...


class HashingEmbedder:
    """Детерминированный feature-hashing эмбеддер (dev/CI, offline).

    Каждому токену — позиция blake2b(token) % dim и знак из бита хэша;
    биграммы добавляют локальный порядок. Вектор L2-нормализован, поэтому
    косинусная близость = скалярное произведение.
    """

    def __init__(self, dim: int = 384, use_bigrams: bool = True):
        self.dim = dim
        self.use_bigrams = use_bigrams

    @property
    def name(self) -> str:
        return f"hashing-{self.dim}"

    def _token_vector(self, token: str, weight: float, vec: List[float]) -> None:
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        n = int.from_bytes(digest, "big")
        idx = n % self.dim
        sign = 1.0 if (n >> 63) & 1 == 0 else -1.0
        vec[idx] += sign * weight

    def embed(self, text: str) -> List[float]:
        tokens = tokenize(text)
        vec = [0.0] * self.dim
        for tok in tokens:
            self._token_vector(tok, 1.0, vec)
        if self.use_bigrams:
            for a, b in zip(tokens, tokens[1:]):
                self._token_vector(f"{a}_{b}", 0.5, vec)
        norm = math.sqrt(sum(x * x for x in vec))
        if norm > 0:
            vec = [x / norm for x in vec]
        return vec

    def embed_batch(self, texts: Sequence[str]) -> List[List[float]]:
        return [self.embed(t) for t in texts]


class SentenceTransformerEmbedder:
    """Прод-эмбеддер: BGE-M3 / e5-small (импорт ТОЛЬКО eager, F-E-07)."""

    def __init__(self, model_name: str = "BAAI/bge-m3"):
        from sentence_transformers import SentenceTransformer  # eager в prod

        self._model = SentenceTransformer(model_name)
        self.dim = int(self._model.get_sentence_embedding_dimension())
        self._model_name = model_name

    @property
    def name(self) -> str:
        return self._model_name

    def embed(self, text: str) -> List[float]:
        vec = self._model.encode(text, normalize_embeddings=True)
        return [float(x) for x in vec]

    def embed_batch(self, texts: Sequence[str]) -> List[List[float]]:
        vecs = self._model.encode(list(texts), normalize_embeddings=True)
        return [[float(x) for x in v] for v in vecs]


def create_embedder(kind: str, dim: int = 384) -> Embedder:
    kind = (kind or "hashing").lower()
    if kind in ("hashing", "dev", ""):
        return HashingEmbedder(dim=dim)
    if kind in ("bge-m3", "bge"):
        return SentenceTransformerEmbedder("BAAI/bge-m3")
    if kind in ("e5-small", "e5"):
        return SentenceTransformerEmbedder("intfloat/multilingual-e5-small")
    raise ValueError(f"неизвестный эмбеддер: {kind!r}")


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    if len(a) != len(b):
        raise ValueError(f"размерности не совпадают: {len(a)} vs {len(b)}")
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


# ----------------------------------------------------------------------------
# Векторное хранилище
# ----------------------------------------------------------------------------

@dataclass
class StoredChunk:
    chunk_id: str
    doc_id: str
    ordinal: int
    text: str
    content_hash: str
    token_count: int
    overlap_tokens_prev: int = 0
    vector: Optional[List[float]] = field(default=None, repr=False)
    metadata: Dict[str, str] = field(default_factory=dict)


class VectorStore(Protocol):
    def upsert(self, chunk: StoredChunk) -> None: ...
    def search(self, query_vector: Sequence[float], top_k: int) -> List[Tuple[StoredChunk, float]]: ...
    def all_chunks(self) -> List[StoredChunk]: ...
    def delete_document(self, doc_id: str) -> int: ...
    def __len__(self) -> int: ...


class InMemoryVectorStore:
    """Cosine-поиск перебором; векторы ожидаются L2-нормализованными."""

    def __init__(self) -> None:
        self._chunks: Dict[str, StoredChunk] = {}

    def upsert(self, chunk: StoredChunk) -> None:
        self._chunks[chunk.chunk_id] = chunk

    def search(self, query_vector: Sequence[float], top_k: int
               ) -> List[Tuple[StoredChunk, float]]:
        scored: List[Tuple[StoredChunk, float]] = []
        for chunk in self._chunks.values():
            if chunk.vector is None:
                continue
            scored.append((chunk, cosine(query_vector, chunk.vector)))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:max(0, top_k)]

    def all_chunks(self) -> List[StoredChunk]:
        return list(self._chunks.values())

    def delete_document(self, doc_id: str) -> int:
        victims = [cid for cid, c in self._chunks.items() if c.doc_id == doc_id]
        for cid in victims:
            del self._chunks[cid]
        return len(victims)

    def __len__(self) -> int:
        return len(self._chunks)


class ChromaVectorStore:
    """Прод-адаптер ChromaDB (F-B-02). Импорты — eager через bootstrap."""

    def __init__(self, persist_dir: str, collection: str = "zt_kb"):
        import chromadb  # noqa: F401 — eager в prod-контуре

        self._client = chromadb.PersistentClient(path=persist_dir)
        self._collection = self._client.get_or_create_collection(collection)
        self._mirror = InMemoryVectorStore()

    def upsert(self, chunk: StoredChunk) -> None:
        self._collection.upsert(
            ids=[chunk.chunk_id],
            embeddings=[chunk.vector] if chunk.vector else None,
            documents=[chunk.text],
            metadatas=[{"doc_id": chunk.doc_id, "ordinal": chunk.ordinal,
                        "content_hash": chunk.content_hash}],
        )
        self._mirror.upsert(chunk)

    def search(self, query_vector: Sequence[float], top_k: int):
        return self._mirror.search(query_vector, top_k)

    def all_chunks(self) -> List[StoredChunk]:
        return self._mirror.all_chunks()

    def delete_document(self, doc_id: str) -> int:
        self._collection.delete(where={"doc_id": doc_id})
        return self._mirror.delete_document(doc_id)

    def __len__(self) -> int:
        return len(self._mirror)
