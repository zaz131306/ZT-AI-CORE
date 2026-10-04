"""Чанкинг с перекрытием (F-A-03: 300–800 токенов, overlap 10–15%).

Токены аппроксимируются whitespace-сегментами с коэффициентом (для русского
текста ~1.3 токена/слово при BPE); при наличии tiktoken/BGE-токенайзера
используется точный счётчик (Eager Loading: загружается до SECCOMP).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Protocol

_WORD_SPLIT = re.compile(r"\S+")


class TokenCounter(Protocol):
    def count(self, text: str) -> int: ...
    def split(self, text: str) -> List[str]: ...


class WordApproxCounter:
    """Аппроксимация: слова + поправочный коэффициент (offline-safe)."""

    def __init__(self, tokens_per_word: float = 1.3):
        self.tokens_per_word = tokens_per_word

    def split(self, text: str) -> List[str]:
        return _WORD_SPLIT.findall(text)

    def count(self, text: str) -> int:
        return int(round(len(self.split(text)) * self.tokens_per_word))


class PreciseCounter:
    """Точный счётчик через tiktoken (если eagerly загружен в bootstrap)."""

    def __init__(self, encoding_name: str = "cl100k_base"):
        import tiktoken  # Eager: только если объявлен в манифесте bootstrap

        self._enc = tiktoken.get_encoding(encoding_name)

    def count(self, text: str) -> int:
        return len(self._enc.encode(text, disallowed_special=()))

    def split(self, text: str) -> List[str]:
        return _WORD_SPLIT.findall(text)


@dataclass(frozen=True)
class TextChunk:
    ordinal: int
    text: str
    token_count: int
    overlap_tokens_prev: int


def _join_tokens(tokens: List[str]) -> str:
    return " ".join(tokens)


def chunk_text(text: str,
               min_tokens: int = 300,
               max_tokens: int = 512,
               hard_max_tokens: int = 800,
               overlap_ratio: float = 0.125,
               counter: Optional[TokenCounter] = None) -> List[TextChunk]:
    """Разбить текст на чанки [min_tokens..max_tokens] с перекрытием.

    Алгоритм: жадное накопление слов до max_tokens; граница уточняется по
    ближайшей sentence-boundary назад (если она не выводит чанк ниже
    min_tokens); перекрытие = последние ``overlap_ratio * len(chunk)``
    токенов предыдущего чанка переносятся в начало следующего.
    """
    if max_tokens > hard_max_tokens:
        raise ValueError(
            f"max_tokens={max_tokens} > hard_max={hard_max_tokens} (F-A-03)")
    if not (0.10 <= overlap_ratio <= 0.15):
        raise ValueError(
            f"overlap_ratio={overlap_ratio} вне диапазона 10–15% (F-A-03)")
    if min_tokens > max_tokens:
        raise ValueError("min_tokens > max_tokens")

    counter = counter or WordApproxCounter()
    tokens = counter.split(text)
    if not tokens:
        return []

    # Префиксные суммы для быстрого подсчёта токенов среза.
    per_token = counter.tokens_per_word if isinstance(counter, WordApproxCounter) else None

    def approx_tokens(n_words: int) -> int:
        if per_token is not None:
            return int(round(n_words * per_token))
        return counter.count(_join_tokens(tokens[:n_words]))

    chunks: List[TextChunk] = []
    start = 0
    total = len(tokens)
    ordinal = 0
    prev_overlap = 0

    def words_for_tokens(target: int) -> int:
        """Сколько слов начиная со start помещается в target токенов."""
        if per_token is not None:
            return max(1, int(target / per_token))
        lo, hi = 1, total - start
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if counter.count(_join_tokens(tokens[start:start + mid])) <= target:
                lo = mid
            else:
                hi = mid - 1
        return lo

    while start < total:
        capacity = words_for_tokens(max_tokens)
        end = min(start + capacity, total)
        if end < total:
            # пытаемся приблизить границу к концу предложения в пределах чанка
            boundary = _find_sentence_boundary(tokens, start, end)
            if boundary is not None and approx_tokens(boundary - start) >= min_tokens:
                end = boundary
        piece = tokens[start:end]
        piece_tokens = approx_tokens(len(piece))
        chunks.append(TextChunk(
            ordinal=ordinal,
            text=_join_tokens(piece),
            token_count=piece_tokens,
            overlap_tokens_prev=prev_overlap,
        ))
        ordinal += 1
        if end >= total:
            break
        overlap_words = max(1, int(round(len(piece) * overlap_ratio)))
        overlap_tokens = approx_tokens(overlap_words)
        start = max(start + 1, end - overlap_words)
        prev_overlap = overlap_tokens
    return chunks


_SENTENCE_END = {".", "!", "?", "…"}


def _find_sentence_boundary(tokens: List[str], start: int, end: int) -> Optional[int]:
    """Последняя граница предложения в (start, end]; None если нет."""
    for i in range(end - 1, max(start, end - 40), -1):
        tok = tokens[i]
        if tok and tok[-1] in _SENTENCE_END:
            return i + 1
    return None
