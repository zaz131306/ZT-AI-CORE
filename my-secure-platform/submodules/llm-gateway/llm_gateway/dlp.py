"""Egress DLP-фильтр LLM Gateway (F-D-04, Info Disclosure в threat model).

Категории:
  * PII: e-mail, телефоны (E.164/РФ), банковские карты (с проверкой Луна),
    СНИЛС, ИНН, паспорт РФ;
  * Секреты/ключи: PEM-заголовки, AWS, GitHub, Slack, OpenAI, Google API,
    JWT, строки подключения с паролями;
  * Внутренние идентификаторы: UUID из конфигурируемого списка;
  * Запрещённые фразы: признаки раскрытия системного промпта/ jailbreak.

Политика: срабатывание правила категории BLOCK → немедленная блокировка
запроса (fail fast, без «частичных» решений). REDACT-правила используются
для санитизации логов.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, List, Optional, Pattern, Sequence


class DlpAction(str, Enum):
    PASS = "PASS"
    BLOCK = "BLOCK"


class DlpCategory(str, Enum):
    PII = "PII"
    SECRET = "SECRET"
    INTERNAL_ID = "INTERNAL_ID"
    FORBIDDEN_PHRASE = "FORBIDDEN_PHRASE"


@dataclass(frozen=True)
class DlpRule:
    rule_id: str
    category: DlpCategory
    pattern: Pattern[str]
    description: str
    # Дополнительный предикат (напр., проверка Луна для кандидатов в карты).
    validator: Optional[Callable[[str], bool]] = None

    def matches(self, text: str) -> List[str]:
        out = []
        for m in self.pattern.finditer(text):
            candidate = m.group(0)
            if self.validator is None or self.validator(candidate):
                out.append(candidate)
        return out


@dataclass
class DlpHit:
    rule_id: str
    category: str
    excerpt: str  # КРАТКИЙ маскированный фрагмент (в лог не должны попадать секреты)


@dataclass
class DlpVerdict:
    action: DlpAction
    hits: List[DlpHit] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.action == DlpAction.BLOCK

    def reasons(self) -> List[str]:
        seen = []
        for h in self.hits:
            key = f"{h.category}:{h.rule_id}"
            if key not in seen:
                seen.append(key)
        return seen


# ----------------------------------------------------------------------------
# Валидаторы
# ----------------------------------------------------------------------------

def luhn_valid(candidate: str) -> bool:
    digits = re.sub(r"\D", "", candidate)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def snils_checksum(candidate: str) -> bool:
    digits = re.sub(r"\D", "", candidate)
    if len(digits) != 11:
        return False
    nums = [int(d) for d in digits[:9]]
    control = int(digits[9:])
    total = sum((9 - i) * n for i, n in enumerate(nums))
    if total < 100:
        check = total
    elif total in (100, 101):
        check = 0
    else:
        check = total % 101
        if check in (100, 101):
            check = 0
    return check == control


def inn_valid(candidate: str) -> bool:
    """Контрольная сумма ИНН (10 или 12 цифр) — снижение false positives."""
    digits = re.sub(r"\D", "", candidate)
    if len(digits) == 10:
        weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        check = sum(w * int(d) for w, d in zip(weights, digits)) % 11 % 10
        return check == int(digits[9])
    if len(digits) == 12:
        w1 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        w2 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        c1 = sum(w * int(d) for w, d in zip(w1, digits)) % 11 % 10
        c2 = sum(w * int(d) for w, d in zip(w2, digits)) % 11 % 10
        return c1 == int(digits[10]) and c2 == int(digits[11])
    return False


# ----------------------------------------------------------------------------
# Банк правил
# ----------------------------------------------------------------------------

def default_rules(extra_internal_uuids: Sequence[str] = ()) -> List[DlpRule]:
    rules: List[DlpRule] = [
        # --- PII -------------------------------------------------------------------
        DlpRule("pii.email", DlpCategory.PII,
                re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
                "адрес электронной почты"),
        DlpRule("pii.phone_e164", DlpCategory.PII,
                re.compile(r"(?<![\w])\+\d{1,3}[\s-]?\(?\d{2,5}\)?[\s-]?\d{2,4}[\s-]?\d{2,4}(?![\w])"),
                "телефон в формате E.164"),
        DlpRule("pii.phone_rf", DlpCategory.PII,
                re.compile(r"(?<![\d+])8[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}(?![\d])"),
                "телефон в формате РФ (8-800/8-9xx…)"),
        DlpRule("pii.bank_card", DlpCategory.PII,
                re.compile(r"(?<!\d)(?:\d[ -]?){13,18}\d(?!\d)"),
                "кандидат в номера банковских карт", validator=luhn_valid),
        DlpRule("pii.snils", DlpCategory.PII,
                re.compile(r"(?<!\d)\d{3}[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{2}(?!\d)"),
                "кандидат в СНИЛС", validator=snils_checksum),
        DlpRule("pii.inn", DlpCategory.PII,
                re.compile(r"(?<!\d)(?:\d{10}|\d{12})(?!\d)"),
                "кандидат в ИНН (10/12 цифр)", validator=inn_valid),
        DlpRule("pii.passport_rf", DlpCategory.PII,
                re.compile(r"(?<!\d)\d{2}[\s-]?\d{2}[\s-]?\d{6}(?!\d)"),
                "кандидат в серию/номер паспорта РФ"),
        # --- Секреты и ключи ----------------------------------------------------------
        DlpRule("secret.pem_private_key", DlpCategory.SECRET,
                re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
                "PEM-заголовок приватного ключа"),
        DlpRule("secret.aws_access_key", DlpCategory.SECRET,
                re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
                "AWS Access Key ID"),
        DlpRule("secret.github_token", DlpCategory.SECRET,
                re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
                "GitHub-токен"),
        DlpRule("secret.slack_token", DlpCategory.SECRET,
                re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
                "Slack-токен"),
        DlpRule("secret.openai_key", DlpCategory.SECRET,
                re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
                "OpenAI API-ключ"),
        DlpRule("secret.google_api_key", DlpCategory.SECRET,
                re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
                "Google API-ключ"),
        DlpRule("secret.jwt", DlpCategory.SECRET,
                re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
                "JWT-токен"),
        DlpRule("secret.generic_bearer", DlpCategory.SECRET,
                re.compile(r"(?i)\b(?:authorization|api[-_]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9._\-]{16,}"),
                "assignment секрета (api_key/token/secret=…)"),
        DlpRule("secret.conn_string", DlpCategory.SECRET,
                re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mssql|mongodb(?:\+srv)?|redis|amqp)://[^\s:'\"]*:[^\s:'\"]*@[^\s'\"]+"),
                "строка подключения с паролем"),
        # --- Запрещённые фразы (раскрытие внутреннего устройства) ------------------------
        DlpRule("phrase.system_prompt_leak", DlpCategory.FORBIDDEN_PHRASE,
                re.compile(r"(?i)(мой|наш)\s+(системный\s+)?промпт|system\s+prompt\s*:\s*|мои\s+инструкции\s+:?|начальные\s+инструкции\s*:"),
                "попытка раскрытия системного промпта"),
        DlpRule("phrase.jailbreak", DlpCategory.FORBIDDEN_PHRASE,
                re.compile(r"(?i)ignore\s+(all\s+)?(previous|above)\s+instructions|забудь\s+(все\s+)?(предыдущие|свои)\s+инструкции|developer\s+mode\s+(enabled|on)|jailbreak"),
                "jailbreak-формулировки"),
    ]
    for uuid_value in extra_internal_uuids:
        rules.append(DlpRule(
            f"internal.uuid.{uuid_value[:8]}", DlpCategory.INTERNAL_ID,
            re.compile(re.escape(uuid_value), re.IGNORECASE),
            "внутренний UUID из конфигурации"))
    return rules


class DlpScanner:
    """Сканер egress-содержимого: первое BLOCK-срабатывание → fail fast."""

    def __init__(self, rules: Optional[Iterable[DlpRule]] = None,
                 extra_internal_uuids: Sequence[str] = ()):
        self.rules: List[DlpRule] = list(rules) if rules is not None \
            else default_rules(extra_internal_uuids)

    def scan(self, text: str, fail_fast: bool = True) -> DlpVerdict:
        hits: List[DlpHit] = []
        for rule in self.rules:
            for match in rule.matches(text):
                hits.append(DlpHit(rule_id=rule.rule_id,
                                   category=rule.category.value,
                                   excerpt=mask_secret(match)))
                if fail_fast:
                    return DlpVerdict(DlpAction.BLOCK, hits)
        return DlpVerdict(DlpAction.BLOCK if hits else DlpAction.PASS, hits)

    def scan_messages(self, messages: Iterable[dict], fail_fast: bool = True) -> DlpVerdict:
        """Сканировать chat-сообщения (role/content) — egress payload D8."""
        blob_parts: List[str] = []
        for msg in messages:
            if isinstance(msg, dict):
                content = msg.get("content")
                if isinstance(content, str):
                    blob_parts.append(content)
                elif isinstance(content, list):  # multipart content
                    for part in content:
                        if isinstance(part, dict) and isinstance(part.get("text"), str):
                            blob_parts.append(part["text"])
        return self.scan("\n".join(blob_parts), fail_fast=fail_fast)


def mask_secret(value: str) -> str:
    """Маскирование для лога: первые 2 и последние 2 символа, длина ≤ 8."""
    if len(value) <= 4:
        return "*" * len(value)
    if len(value) <= 8:
        return value[0] + "*" * (len(value) - 2) + value[-1]
    return f"{value[:2]}{'*' * 6}{value[-2:]}(len={len(value)})"
