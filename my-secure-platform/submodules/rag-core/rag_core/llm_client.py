"""LLM-клиент D8 (F-D-01/02): локальный Qwen 2.5 / L4 Gateway / offline-режим.

Режимы:
  * extractive — детерминированный офлайн-генератор (dev/CI): ответ
    составляется из предложений наиболее релевантного чанка. НЕ является
    LLM; служит для сквозных тестов пайплайна и каскадного валидатора;
  * local — HTTP к локальному Qwen 2.5 (F-D-01, OpenAI-совместимый API);
  * gateway — ТОЛЬКО через L4 (F-D-02): mTLS-сертификат D8 (TTL ≤ 5 мин)
    выдаётся эмитентом после Remote Attestation (F-H-05).

Сетевые вызовы из D8 в prod выполняются через шину L5→L4 (AF_UNIX →
LLM Gateway), прямые AF_INET-соединения запрещены SECCOMP/eBPF (AC-01);
HTTP-клиент здесь — контракт уровня сообщений.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import List, Optional

from .prompts.isolation import FALLBACK_ANSWER, IsolatedPrompt

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?…])\s+")


class LlmError(RuntimeError):
    pass


@dataclass
class LlmResponse:
    text: str
    model_id: str
    latency_ms: float


class ExtractiveLlm:
    """Offline-генератор: извлекает предложения из топ-чанка, релевантные вопросу."""

    model_id = "extractive-offline"

    def generate(self, prompt: IsolatedPrompt, top_contexts: List[str]) -> LlmResponse:
        started = time.monotonic()
        from .kb.store import tokenize

        question_tokens = set(tokenize(prompt.user.content.split("<<<QUESTION-START>>>")[-1]
                                       .split("<<<QUESTION-END>>>")[0]))
        best_sentences: List[str] = []
        for ctx in top_contexts[:2]:
            sentences = [s.strip() for s in _SENTENCE_SPLIT.split(ctx) if s.strip()]
            scored = []
            for s in sentences:
                toks = set(tokenize(s))
                overlap = len(toks & question_tokens)
                # Анти-bridging: одиночный общий токен (число, предлог) —
                # НЕ основание считать предложение ответом, если запрос
                # длиннее 2 токенов (AC-06).
                if overlap < 2 and not (overlap == 1 and len(question_tokens) <= 2):
                    continue
                scored.append((overlap / (len(toks) or 1), s))
            scored.sort(key=lambda p: p[0], reverse=True)
            best_sentences.extend(s for score, s in scored[:2] if score > 0)
        text = " ".join(best_sentences[:3]).strip()
        if not text:
            # контекст не дал релевантных предложений — честный fallback
            text = FALLBACK_ANSWER
        return LlmResponse(text=text, model_id=self.model_id,
                           latency_ms=(time.monotonic() - started) * 1000)


class HttpLlmClient:
    """OpenAI-совместимый HTTP-клиент (локальный Qwen или L4 Gateway)."""

    def __init__(self, base_url: str, timeout: float = 15.0,
                 client_cert: Optional[tuple[str, str]] = None,
                 ca_bundle: Optional[str] = None, model: str = "qwen2.5-14b"):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.client_cert = client_cert
        self.ca_bundle = ca_bundle
        self.model = model

    def _ssl_context(self):
        import ssl
        ctx = ssl.create_default_context(cafile=self.ca_bundle)
        if self.client_cert:
            ctx.load_cert_chain(*self.client_cert)
        return ctx

    def generate(self, prompt: IsolatedPrompt, top_contexts: List[str]) -> LlmResponse:
        started = time.monotonic()
        request_body = {
            "model": self.model,
            "messages": prompt.to_messages(),
            "temperature": 0.0,   # детерминизм ответов для аудита
            "max_tokens": 1024,
        }
        data = json.dumps(request_body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/v1/chat/completions", data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=self._ssl_context()) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LlmError(f"LLM endpoint недоступен ({self.base_url}): {exc}") from exc
        try:
            text = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LlmError(f"некорректный ответ LLM: {payload!r:.300}") from exc
        return LlmResponse(text=str(text), model_id=str(payload.get("model", self.model)),
                           latency_ms=(time.monotonic() - started) * 1000)


def create_llm_client(mode: str, gateway_url: str = "", local_url: str = "",
                      timeout: float = 15.0,
                      client_cert: Optional[tuple[str, str]] = None,
                      ca_bundle: Optional[str] = None):
    mode = (mode or "extractive").lower()
    if mode == "extractive":
        return ExtractiveLlm()
    if mode == "gateway":
        if not gateway_url:
            raise LlmError("режим gateway требует ZT_RAG_GATEWAY (F-D-02)")
        return HttpLlmClient(gateway_url, timeout, client_cert, ca_bundle,
                             model="external-via-gateway")
    if mode == "local":
        if not local_url:
            raise LlmError("режим local требует ZT_RAG_LOCAL_LLM (F-D-01)")
        return HttpLlmClient(local_url, timeout, model="qwen2.5-14b-local")
    raise LlmError(f"неизвестный режим LLM: {mode!r}")
