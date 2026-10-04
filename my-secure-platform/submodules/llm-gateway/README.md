# llm-gateway — L4-прокси когнитивного контура

Единственная легальная точка выхода D8 во внешние LLM API (ТЗ v2.4, F-D-02/04).

## Конвейер запроса (F-D-04)

```text
D8 (rag-core) ──mTLS(TLS1.3, клиентский cert TTL ≤ 5 мин)──▶ LLM Gateway
   1. mTLS: CERT_REQUIRED + проверка CA + ПОЛИТИКА TTL (сертификат
      с сроком > 5 мин отклоняется даже с валидной цепочкой)
   2. Rate-limit: token bucket на CN клиента (N/мин + burst)
   3. Egress DLP: PII (e-mail/телефоны/карты+Luhn/СНИЛС+checksum/ИНН/паспорт),
      секреты (PEM/AWS/GitHub/Slack/OpenAI/Google/JWT/conn-strings),
      запрещённые фразы (раскрытие промпта, jailbreak) → 451, fail fast
   4. Allow-list доменов (защита от suffix/userinfo-трюков) → 403
   5. Circuit breaker на хост (CLOSED→OPEN→HALF_OPEN) → 503 + fallback Qwen
   6. Upstream (mock в dev / HTTPS в prod)
   7. DLP-скан ответа (defense in depth)
   8. Egress WORM-лог: hash-chain запись (payload_hash + метаданные) +
      публикация в L7 (audit.proto:Append), при недоступности шины — спул
   9. Prometheus /metrics
```

## Запуск

```bash
# Dev-контур (compose поднимает CA/сертификаты через volume keys/):
python3 -m llm_gateway.main --port 8443 --mock-upstream \
    --cert keys/gateway-server.crt --key keys/gateway-server.key \
    --ca keys/zt-ca.crt --allowlist api.provider-one.example

# Тесты (53, включая реальные mTLS-handshake'и):
PYTHONPATH=. python3 -m pytest -q tests

# Краткоживущий клиентский сертификат D8 (TTL 5 мин):
certs/issue_short_lived.sh keys/zt-ca.crt keys/zt-ca.key d8-rag-core 300 out/client
```

## Конфигурация (env)

| Переменная | Default | Требование ТЗ |
|---|---|---|
| `ZT_GATEWAY_CLIENT_MAX_TTL_SECS` | 300 | F-D-04: ≤ 300 |
| `ZT_GATEWAY_RATE_LIMIT_PER_MIN` | 60 | F-D-04 |
| `ZT_GATEWAY_ALLOWLIST` | — (пустой запрещён) | F-D-04 |
| `ZT_BREAKER_FAIL_THRESHOLD` / `ZT_BREAKER_RESET_SECS` | 5 / 30 | F-D-04 |
| `ZT_GATEWAY_TLS_MIN` | 1.3 | Приложение Б |
| `ZT_GATEWAY_MOCK_UPSTREAM` | 0 | dev/chaos |

Runtime — **stdlib-only** (asyncio + ssl); `blake3` опционален (канонический
хэш egress-лога; fallback blake2b). TLS 1.3, X25519, cipher-suites
`TLS_AES_256_GCM_SHA384` / `TLS_CHACHA20_POLY1305_SHA256`.

Remote Attestation (F-H-05): в prod перед выдачей клиентского сертификата
эмитент требует TPM Quote (PCR[0-15] ↔ SBOM); точка расширения —
`upstream.attest()`.
