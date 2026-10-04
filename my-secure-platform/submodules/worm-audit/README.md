# worm-audit — неизменяемый журнал (L7)

Rust-реализация WORM-аудита ZT-AI-CORE (ТЗ v2.4, Раздел 3.5, Приложение Б п.3,
docs/07-worm-audit.md).

## Гарантии

* **BLAKE3 hash-chain (F-G-01/02)**: `chain_hash = BLAKE3(prev ‖ payload_hash ‖
  timestamp ‖ nonce)`, genesis = 32×0x00;
* **Ed25519-подпись** каждой записи и чекпоинтов (в prod ключ в TPM/HSM —
  F-H-03; стендовый провайдер — `SeedSigner`);
* **Anti-replay (F-G-03)**: уникальный nonce (getrandom) + TTL-окно ±300 с;
* **Чекпоинты (F-G-04)**: ≥ 1000 записей ИЛИ ≥ 60 с; dual-anchor:
  TPM NV-Counter (≤ 1 записи/час, износ ≥ 80% → алерт) + внешний WORM
  (S3 Object Lock; dev — `DirectoryAnchor` с chmod-имитацией Object Lock);
* **Anti-truncation (AC-03)**: сверка при старте — `seq_TPM > seq_local` или
  `seq_ext > seq_local` → **TRUNCATION**: блокировка записи + RECOVERY;
* **Буферизация при отказе якоря**: S3 недоступен > 5 мин → DEGRADED,
  чекпоинты в `LocalCheckpointBuffer`, авто-слив после восстановления;
* **NF-03**: ≥ 10 000 записей/с (факт в release: **~26 700 rec/s** c подписью
  каждой записи, group-commit).

## Модули

| Модуль | Назначение |
|---|---|
| `src/record.rs` | Запись, chain_hash, getrandom-nonce, JSONL-кодек |
| `src/chain.rs` | ChainWriter (append-only, sync-политики), NonceCache, verify_chain |
| `src/checkpoint.rs` | Чекпоинты: хэш, Ed25519-подпись, планировщик 1000/60с |
| `src/anchors.rs` | TpmAnchor (rate-limit 1/ч, износ), DirectoryAnchor, FailingAnchor, LocalCheckpointBuffer |
| `src/reconcile.rs` | Чистая функция сверки F-G-04 (все 5 вердиктов) |
| `src/service.rs` | AuditService: append+auto-checkpoint, reconcile, ingest-spool |
| `src/server.rs` | UDS-сервер контракта `audit.proto` + SO_PEERCRED |
| `src/main.rs` | CLI: `serve` / `verify` / `benchmark` / `ingest-spool` / `healthcheck` |

## Использование

```bash
cargo test                                   # 56 тестов
cargo run --release -- benchmark --chain-dir /tmp/b --records 20000   # NF-03
zt-worm-audit serve --socket /run/zt-core/audit.sock \
    --chain /var/worm/audit-chain.jsonl --checkpoints /var/worm/checkpoints.jsonl \
    --anchor-dir /var/worm/anchors --tpm-dir /var/lib/zt-core/tpm-mock
zt-worm-audit verify --chain /var/worm/audit-chain.jsonl
zt-worm-audit ingest-spool --chain ... --spool /var/rag/audit-spool.jsonl --remove
```

Прод-подключения: `TpmOps` → tss2/tpm2-tools (TPM 2.0) или PKCS#11 HSM;
`ExternalAnchor` → S3 PutObject + Object Lock (Compliance mode).
