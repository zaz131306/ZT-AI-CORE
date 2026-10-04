"""Очистка и санитайзинг чанков (F-A-02, контрмера Prompt Injection).

RAG-контекст — НЕдоверенные данные. Санитайзер нейтрализует:
  * управляющие символы и невидимые unicode-маркеры (RLO/LRO/zero-width);
  * попытки инъекций ролевых маркеров («system:», «инструкции:», chat-теги);
  * формулировки-инжекции («ignore previous instructions» и т.п.) — чанк
    ПОМЕЧАЕТСЯ как подозрительный (rejected_poison в ingestion-отчёте);
  * избыточные пробельные последовательности.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import List

# Невидимые/направленные символы, используемые для скрытия инъекций.
_INVISIBLE = dict.fromkeys(
    map(ord, "\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
             "\u2060\u2066\u2067\u2068\u2069\ufeff"),
    None)

_INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)"),
    re.compile(r"(?i)\bdisregard\s+(the\s+)?(system|previous)\s+prompt"),
    re.compile(r"(?i)you\s+are\s+now\s+(in\s+)?(developer|god|dan)\s*mode"),
    re.compile(r"(?i)reveal\s+(your|the)\s+system\s+prompt"),
    re.compile(r"забудь(те)?\s+(все\s+)?(предыдущие|свои)\s+инструкции", re.IGNORECASE),
    re.compile(r"игнорируй(те)?\s+(все\s+)?(предыдущие|системные)\s+инструкции", re.IGNORECASE),
    re.compile(r"(?i)<\s*/?\s*(system|assistant|tool)\s*>"),
]

_ROLE_MARKER = re.compile(r"(?i)\b(system|assistant|tool|developer)\s*:")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass
class SanitizeResult:
    text: str
    suspicious: bool = False
    findings: List[str] = field(default_factory=list)


def strip_control_chars(text: str) -> str:
    text = text.translate(_INVISIBLE)
    text = _CONTROL_CHARS.sub("", text)
    # нормализация конфузаблей (NFKC) — единая форма символов
    return unicodedata.normalize("NFKC", text)


def sanitize_chunk(text: str, strict: bool = True) -> SanitizeResult:
    """Очистка чанка KB перед индексацией/подачей в промпт.

    :param strict: при обнаружении инъекционных формулировок чанк помечается
                   suspicious=True (ingestion отклоняет его: REJECTED_POISON).
    """
    findings: List[str] = []
    cleaned = strip_control_chars(text)

    for pattern in _INJECTION_PATTERNS:
        if pattern.search(cleaned):
            findings.append(f"injection_pattern:{pattern.pattern[:40]}")
            if strict:
                return SanitizeResult(text=cleaned, suspicious=True, findings=findings)

    # Ролевые маркеры нейтрализуются в ЛЮБОЙ позиции (экранируются),
    # чтобы данные не имитировали инструкции/роли чат-формата (F-C-05).
    if _ROLE_MARKER.search(cleaned):
        findings.append("role_marker_escaped")
        cleaned = _ROLE_MARKER.sub(lambda m: f"[{m.group(1).lower()}] ", cleaned)

    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    return SanitizeResult(text=cleaned, suspicious=False, findings=findings)


def escape_context_delimiters(text: str) -> str:
    """Экранирование разделителей контекстного конверта (F-C-05):
    данные не могут «закрыть» свой блок и выдать себя за инструкции."""
    return (text
            .replace("<<<", "<\\u200b<<")
            .replace(">>>", ">\\u200b>>")
            .replace("[[CONTEXT-END]]", "[[CONTEXT\\u2011END]]"))
