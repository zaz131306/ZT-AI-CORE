"""Уровень 1 каскада: rule-based (~0.1 мс) — regex/словари, fail fast.

Проверяет ОТВЕТ модели: PII, секреты/ключи, запрещённые фразы
(раскрытие промпта, jailbreak-маркеры). Срабатывание → немедленная
блокировка (F-D-03 п.1).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern, Tuple

# Компактный банк паттернов (единый источник с llm-gateway DLP, но
# дублирован намеренно: D8 не импортирует модули L4 — границы доверий).
_PATTERNS: List[Tuple[str, str, Pattern]] = [
    ("pii.email", "PII", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("pii.phone", "PII", re.compile(r"(?<![\w+])\+\d{7,15}(?![\w])|8[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}")),
    ("pii.passport_rf", "PII", re.compile(r"(?<!\d)\d{4}\s?\d{6}(?!\d)")),
    ("secret.pem_key", "SECRET", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("secret.aws_key", "SECRET", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("secret.generic_token", "SECRET", re.compile(r"\b(?:ghp_|gho_|xox[baprs]-|sk-(?:proj-)?|AIza)[A-Za-z0-9_-]{10,}")),
    ("secret.jwt", "SECRET", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("secret.assignment", "SECRET", re.compile(r"(?i)\b(?:api[-_]?key|secret|password|пароль)\s*[:=]\s*['\"]?[A-Za-z0-9._\-]{8,}")),
    ("phrase.prompt_leak", "FORBIDDEN_PHRASE", re.compile(
        r"(?i)(мой|наш)\s+(системный\s+)?промпт|system\s+prompt|мои\s+инструкции\s*:")),
    ("phrase.jailbreak_ack", "FORBIDDEN_PHRASE", re.compile(
        r"(?i)developer\s+mode|jailbreak|режим\s+разработчика\s+включ")),
]

# Запрещённые фразы-маркеры галлюцинаций о внутренних механизмах.
_INTERNAL_LEAK = re.compile(
    r"(?i)zt-ai-core\s+(v\d|версия)|worm-лог|seccomp-профиль|bwrap|hash-chain")


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    category: str
    masked: str


@dataclass(frozen=True)
class RuleVerdict:
    blocked: bool
    hits: List[RuleHit]


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * min(6, len(value) - 4) + value[-2:]


def rule_check(answer: str, extra_forbidden: List[str] | None = None) -> RuleVerdict:
    """Полная проверка ответа правилом (~0.1 мс на KB-текст)."""
    hits: List[RuleHit] = []
    for rule_id, category, pattern in _PATTERNS:
        for m in pattern.finditer(answer):
            hits.append(RuleHit(rule_id, category, _mask(m.group(0))))
            break  # fail fast по каждому правилу — одного попадания достаточно
    if _INTERNAL_LEAK.search(answer):
        hits.append(RuleHit("phrase.internal_leak", "FORBIDDEN_PHRASE",
                            _mask(_INTERNAL_LEAK.search(answer).group(0))))
    for phrase in (extra_forbidden or []):
        if phrase.lower() in answer.lower():
            hits.append(RuleHit(f"custom.{phrase[:16]}", "FORBIDDEN_PHRASE",
                                _mask(phrase)))
    return RuleVerdict(blocked=bool(hits), hits=hits)
